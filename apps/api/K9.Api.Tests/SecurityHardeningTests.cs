using System.Net;
using System.Net.Http.Json;
using K9.Api.Organizations;
using K9.Api.Tests.Infrastructure;
using Npgsql;

namespace K9.Api.Tests;

/// <summary>
/// Hostile inputs and privilege boundaries: the SECURITY DEFINER functions, what the
/// runtime role may do, and attacker-controlled values reaching SQL.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class SecurityHardeningTests(K9ApiFactory api)
{
    private static readonly string[] DefinerFunctions = ["k9_upsert_user", "k9_find_user_id_by_email"];

    // ---- SECURITY DEFINER functions --------------------------------------------------

    [Fact]
    public async Task Definer_functions_pin_an_empty_search_path()
    {
        await using var connection = await Open(api.SuperuserConnectionString);
        foreach (var name in DefinerFunctions)
        {
            await using var command = new NpgsqlCommand(
                "SELECT prosecdef, array_to_string(proconfig, ',') FROM pg_proc WHERE proname = @name", connection);
            command.Parameters.AddWithValue("name", name);
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync(), $"{name} not found");
            Assert.True(reader.GetBoolean(0), $"{name} should be SECURITY DEFINER");
            Assert.Equal("search_path=\"\"", reader.GetString(1));
        }
    }

    [Fact]
    public async Task Only_the_runtime_role_can_execute_definer_functions()
    {
        // A role with CONNECT and schema USAGE but no explicit grant: models PUBLIC.
        var password = Guid.NewGuid().ToString("N");
        var role = $"intruder_{Guid.NewGuid():N}"[..20];
        await using (var admin = await Open(api.SuperuserConnectionString))
        {
            await Execute(admin, $"CREATE ROLE {role} LOGIN PASSWORD '{password}'");
            await Execute(admin, $"GRANT CONNECT ON DATABASE k9 TO {role}");
            await Execute(admin, $"GRANT USAGE ON SCHEMA public TO {role}");
        }

        var connectionString = new NpgsqlConnectionStringBuilder(api.AppConnectionString) { Username = role, Password = password }.ConnectionString;
        await using var intruder = await Open(connectionString);
        foreach (var sql in new[]
        {
            "SELECT k9_upsert_user('forged-subject', 'x@k9.test', 'x')",
            "SELECT k9_find_user_id_by_email('x@k9.test')",
        })
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => Execute(intruder, sql));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        }
    }

    public static TheoryData<string?> InvalidSubjects => new() { null, "", " ", "has space", "tab\tin", new string('s', 256) };

    [Theory]
    [MemberData(nameof(InvalidSubjects))]
    public async Task Upsert_rejects_invalid_subjects(string? subject)
    {
        await using var connection = await Open(api.AppConnectionString);
        await using var command = new NpgsqlCommand("SELECT k9_upsert_user(@subject, NULL, NULL)", connection);
        command.Parameters.AddWithValue("subject", (object?)subject ?? DBNull.Value);
        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteScalarAsync());
        Assert.Equal(PostgresErrorCodes.InvalidParameterValue, error.SqlState);
    }

    [Fact]
    public async Task Runtime_role_cannot_shadow_objects_used_by_definer_functions()
    {
        await using var connection = await Open(api.AppConnectionString);
        foreach (var sql in new[]
        {
            "CREATE TEMP TABLE users (id uuid)",
            "CREATE FUNCTION public.lower(text) RETURNS text LANGUAGE sql AS 'SELECT $1'",
            "CREATE SCHEMA evil",
        })
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => Execute(connection, sql));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        }
    }

    // ---- Hostile token claims ---------------------------------------------------------

    [Fact]
    public async Task Hostile_profile_claims_are_sanitised_not_executed()
    {
        var hostileName = "Robert'); DROP TABLE users;--\u0000\u0007" + new string('x', 5000);
        var user = new TestUser($"sub-{Guid.NewGuid():N}", new string('a', 400) + "@k9.test", hostileName);
        var client = api.ClientFor(user);

        var me = await client.GetFromJsonAsync<MeResponse>("/api/me", Json.Options);

        Assert.Null(me!.Email);
        Assert.Equal(200, me.DisplayName!.Length);
        Assert.StartsWith("Robert'); DROP TABLE users;--x", me.DisplayName);
        Assert.DoesNotContain(me.DisplayName, char.IsControl);

        // The users table is intact and the same identity resolves to the same user.
        var again = await client.GetFromJsonAsync<MeResponse>("/api/me", Json.Options);
        Assert.Equal(me.Id, again!.Id);
    }

    public static TheoryData<string> MalformedSubjects => new() { new string('s', 256), "has space", "nul\0byte", "new\nline" };

    [Theory]
    [MemberData(nameof(MalformedSubjects))]
    public async Task Malformed_subject_is_unauthenticated_not_a_server_error(string subject)
    {
        var user = new TestUser(subject, "long@k9.test", "Long");
        var response = await api.ClientFor(user).GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Emails_are_matched_case_insensitively_and_stored_normalised()
    {
        var invitee = new TestUser($"sub-{Guid.NewGuid():N}", $"  Mixed.Case-{Guid.NewGuid():N}@K9.Test ", "Invitee");
        var me = await api.ClientFor(invitee).GetFromJsonAsync<MeResponse>("/api/me", Json.Options);
        Assert.Equal(invitee.Email.Trim().ToLowerInvariant(), me!.Email);

        var owner = api.ClientFor(TestUser.Create("Owner"));
        var created = await (await owner.PostAsJsonAsync("/api/organizations", new CreateOrganizationRequest("Org"), Json.Options))
            .Content.ReadFromJsonAsync<OrganizationResponse>(Json.Options);
        var added = await owner.PostAsJsonAsync(
            $"/api/organizations/{created!.Id}/members", new AddMemberRequest(invitee.Email.ToUpperInvariant(), OrganizationRole.Viewer), Json.Options);
        Assert.Equal(HttpStatusCode.Created, added.StatusCode);
    }

    // ---- Hostile request input ---------------------------------------------------------

    public static TheoryData<string> HostileOrganizationIds => new()
    {
        "' OR '1'='1",
        "00000000-0000-0000-0000-000000000000' OR 1=1--",
        "%27%20OR%201%3D1--",
        "..%2F..%2Fhealth%2Flive",
    };

    [Theory]
    [MemberData(nameof(HostileOrganizationIds))]
    public async Task Hostile_organization_ids_never_reach_the_database(string organizationId)
    {
        var client = api.ClientFor(TestUser.Create("Mallory"));
        var response = await client.GetAsync($"/api/organizations/{organizationId}/members");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Hostile_names_and_emails_are_stored_as_data()
    {
        var owner = api.ClientFor(TestUser.Create("Owner"));
        const string name = "Acme'; DELETE FROM memberships;-- <script>alert(1)</script>";
        var response = await owner.PostAsJsonAsync("/api/organizations", new CreateOrganizationRequest(name), Json.Options);
        var organization = await response.Content.ReadFromJsonAsync<OrganizationResponse>(Json.Options);
        Assert.Equal(name, organization!.Name);

        var lookup = await owner.PostAsJsonAsync(
            $"/api/organizations/{organization.Id}/members", new AddMemberRequest("x' OR '1'='1", OrganizationRole.Viewer), Json.Options);
        Assert.Equal(HttpStatusCode.NotFound, lookup.StatusCode);

        var members = await owner.GetFromJsonAsync<List<MemberResponse>>($"/api/organizations/{organization.Id}/members", Json.Options);
        Assert.Single(members!);
    }

    [Fact]
    public async Task Unknown_roles_are_rejected()
    {
        var owner = api.ClientFor(TestUser.Create("Owner"));
        var organization = await (await owner.PostAsJsonAsync("/api/organizations", new CreateOrganizationRequest("Org"), Json.Options))
            .Content.ReadFromJsonAsync<OrganizationResponse>(Json.Options);

        foreach (var body in new[] { """{"email":"a@k9.test","role":"SuperAdmin"}""", """{"email":"a@k9.test","role":99}""" })
        {
            var response = await owner.PostAsync(
                $"/api/organizations/{organization!.Id}/members", new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    private static async Task<NpgsqlConnection> Open(string connectionString)
    {
        var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        return connection;
    }

    private static async Task Execute(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}
