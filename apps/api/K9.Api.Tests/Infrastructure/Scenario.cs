using System.Net;
using System.Net.Http.Json;
using K9.Api.Audit;
using K9.Api.Organizations;
using Npgsql;

namespace K9.Api.Tests.Infrastructure;

/// <summary>A signed-in test user: their HTTP client, identity and K9 user id.</summary>
public sealed record Actor(HttpClient Client, TestUser User, Guid Id);

public static class Scenario
{
    public static async Task<Actor> SignInAsync(this K9ApiFactory api, string name)
    {
        var user = TestUser.Create(name);
        var client = api.ClientFor(user);
        var me = await client.GetFromJsonAsync<MeResponse>("/api/me", Json.Options);
        return new Actor(client, user, me!.Id);
    }

    public static async Task<Guid> CreateOrganizationAsync(this Actor actor, string name = "Org")
    {
        var response = await actor.Client.PostAsJsonAsync("/api/organizations", new CreateOrganizationRequest(name), Json.Options);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<OrganizationResponse>(Json.Options))!.Id;
    }

    public static Task<HttpResponseMessage> AddMemberAsync(this Actor actor, Guid organizationId, Actor member, OrganizationRole role) =>
        actor.Client.PostAsJsonAsync($"/api/organizations/{organizationId}/members", new AddMemberRequest(member.User.Email, role), Json.Options);

    public static Task<HttpResponseMessage> ChangeRoleAsync(this Actor actor, Guid organizationId, Guid memberId, OrganizationRole role) =>
        actor.Client.PatchAsJsonAsync($"/api/organizations/{organizationId}/members/{memberId}", new ChangeRoleRequest(role), Json.Options);

    public static Task<HttpResponseMessage> RemoveMemberAsync(this Actor actor, Guid organizationId, Guid memberId) =>
        actor.Client.DeleteAsync($"/api/organizations/{organizationId}/members/{memberId}");

    public static async Task<AuditPage> AuditAsync(this Actor actor, Guid organizationId, string query = "")
    {
        var response = await actor.Client.GetAsync($"/api/organizations/{organizationId}/audit-events{query}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<AuditPage>(Json.Options))!;
    }

    public static string CorrelationIdOf(HttpResponseMessage response) =>
        response.Headers.GetValues(CorrelationId.HeaderName).Single();

    /// <summary>Platform-wide view of audit rows, as an operator would query it.</summary>
    public static async Task<List<Dictionary<string, object?>>> AuditRowsAsync(this K9ApiFactory api, string correlationId)
    {
        await using var connection = new NpgsqlConnection(api.SuperuserConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT id, organization_id, actor_user_id, action, outcome, resource_type, resource_id, details::text AS details, row_to_json(a)::text AS raw " +
            "FROM audit_events a WHERE correlation_id = @id ORDER BY id", connection);
        command.Parameters.AddWithValue("id", correlationId);
        await using var reader = await command.ExecuteReaderAsync();
        var rows = new List<Dictionary<string, object?>>();
        while (await reader.ReadAsync())
        {
            rows.Add(Enumerable.Range(0, reader.FieldCount).ToDictionary(reader.GetName, i => reader.IsDBNull(i) ? null : reader.GetValue(i)));
        }
        return rows;
    }

    public static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}
