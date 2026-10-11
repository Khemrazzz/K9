using System.Net;
using System.Net.Http.Json;
using K9.Api.Data;
using K9.Api.Organizations;
using K9.Api.Tenancy;
using K9.Api.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace K9.Api.Tests;

[Collection(ApiCollection.Name)]
public sealed class TenantIsolationTests(K9ApiFactory api)
{
    // ---- Through the API ------------------------------------------------------------

    [Fact]
    public async Task Creator_becomes_owner_and_sees_only_their_organization()
    {
        var (alice, acme) = await SignUpWithOrganization("Alice", "Acme");
        var (_, globex) = await SignUpWithOrganization("Bob", "Globex");

        var me = await alice.GetFromJsonAsync<MeResponse>("/api/me", Json.Options);

        var only = Assert.Single(me!.Organizations);
        Assert.Equal(acme.Id, only.Id);
        Assert.Equal(OrganizationRole.Owner, only.Role);
        Assert.DoesNotContain(me.Organizations, o => o.Id == globex.Id);
    }

    [Fact]
    public async Task Member_of_one_organization_cannot_reach_another()
    {
        var (alice, _) = await SignUpWithOrganization("Alice", "Acme");
        var (_, globex) = await SignUpWithOrganization("Bob", "Globex");

        Assert.Equal(HttpStatusCode.Forbidden, (await alice.GetAsync($"/api/organizations/{globex.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await alice.GetAsync($"/api/organizations/{globex.Id}/members")).StatusCode);

        var me = await alice.GetFromJsonAsync<MeResponse>("/api/me", Json.Options);
        var addSelf = await alice.PostAsJsonAsync(
            $"/api/organizations/{globex.Id}/members", new AddMemberRequest(me!.Email, OrganizationRole.Owner), Json.Options);
        Assert.Equal(HttpStatusCode.Forbidden, addSelf.StatusCode);
    }

    [Fact]
    public async Task Unknown_or_malformed_organization_ids_are_not_found_or_forbidden()
    {
        var (alice, _) = await SignUpWithOrganization("Alice", "Acme");

        Assert.Equal(HttpStatusCode.Forbidden, (await alice.GetAsync($"/api/organizations/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await alice.GetAsync("/api/organizations/not-a-guid")).StatusCode);
    }

    [Fact]
    public async Task Roles_limit_what_a_member_can_do()
    {
        var aliceUser = TestUser.Create("Alice");
        var alice = api.ClientFor(aliceUser);
        await alice.GetAsync("/api/me"); // first sign-in creates the K9 user
        var (bob, globex) = await SignUpWithOrganization("Bob", "Globex");

        var added = await bob.PostAsJsonAsync(
            $"/api/organizations/{globex.Id}/members", new AddMemberRequest(aliceUser.Email, OrganizationRole.Viewer), Json.Options);
        Assert.Equal(HttpStatusCode.Created, added.StatusCode);

        // A viewer can read the organization and its members...
        var organization = await alice.GetFromJsonAsync<OrganizationResponse>($"/api/organizations/{globex.Id}", Json.Options);
        Assert.Equal(OrganizationRole.Viewer, organization!.Role);
        var members = await alice.GetFromJsonAsync<List<MemberResponse>>($"/api/organizations/{globex.Id}/members", Json.Options);
        Assert.Equal(2, members!.Count);

        // ...but cannot add members.
        var carol = TestUser.Create("Carol");
        await api.ClientFor(carol).GetAsync("/api/me");
        var viewerAdds = await alice.PostAsJsonAsync(
            $"/api/organizations/{globex.Id}/members", new AddMemberRequest(carol.Email, OrganizationRole.Viewer), Json.Options);
        Assert.Equal(HttpStatusCode.Forbidden, viewerAdds.StatusCode);
    }

    [Fact]
    public async Task Admin_cannot_grant_owner()
    {
        var aliceUser = TestUser.Create("Alice");
        var alice = api.ClientFor(aliceUser);
        await alice.GetAsync("/api/me");
        var carol = TestUser.Create("Carol");
        await api.ClientFor(carol).GetAsync("/api/me");
        var (bob, globex) = await SignUpWithOrganization("Bob", "Globex");
        await bob.PostAsJsonAsync($"/api/organizations/{globex.Id}/members", new AddMemberRequest(aliceUser.Email, OrganizationRole.Admin), Json.Options);

        var promote = await alice.PostAsJsonAsync(
            $"/api/organizations/{globex.Id}/members", new AddMemberRequest(carol.Email, OrganizationRole.Owner), Json.Options);
        Assert.Equal(HttpStatusCode.Forbidden, promote.StatusCode);

        var asAnalyst = await alice.PostAsJsonAsync(
            $"/api/organizations/{globex.Id}/members", new AddMemberRequest(carol.Email, OrganizationRole.Analyst), Json.Options);
        Assert.Equal(HttpStatusCode.Created, asAnalyst.StatusCode);
    }

    // ---- Directly against Postgres, with no application filters --------------------
    // These prove row-level security holds even if an endpoint forgets a WHERE clause.

    [Fact]
    public async Task Database_returns_only_the_active_organizations_rows()
    {
        var (alice, acme) = await SignUpWithOrganization("Alice", "Acme");
        var (bob, globex) = await SignUpWithOrganization("Bob", "Globex");
        var aliceId = (await alice.GetFromJsonAsync<MeResponse>("/api/me", Json.Options))!.Id;
        var bobId = (await bob.GetFromJsonAsync<MeResponse>("/api/me", Json.Options))!.Id;

        var context = new RequestContext();
        context.SignIn(aliceId);
        context.EnterOrganization(acme.Id, OrganizationRole.Owner);
        await using var db = CreateDb(context);

        var organizations = await db.Organizations.Select(o => o.Id).ToListAsync();
        var memberships = await db.Memberships.Select(m => m.OrganizationId).ToListAsync();
        var users = await db.Users.Select(u => u.Id).ToListAsync();

        Assert.Equal(new[] { acme.Id }, organizations);
        Assert.All(memberships, id => Assert.Equal(acme.Id, id));
        Assert.Contains(aliceId, users);
        Assert.DoesNotContain(bobId, users);
        Assert.DoesNotContain(globex.Id, organizations);
    }

    [Fact]
    public async Task Database_returns_nothing_without_a_request_context()
    {
        await SignUpWithOrganization("Alice", "Acme");

        await using var db = CreateDb(new RequestContext());

        Assert.Empty(await db.Organizations.ToListAsync());
        Assert.Empty(await db.Memberships.ToListAsync());
        Assert.Empty(await db.Users.ToListAsync());
    }

    [Fact]
    public async Task Database_rejects_writes_into_another_organization()
    {
        var (alice, acme) = await SignUpWithOrganization("Alice", "Acme");
        var (_, globex) = await SignUpWithOrganization("Bob", "Globex");
        var aliceId = (await alice.GetFromJsonAsync<MeResponse>("/api/me", Json.Options))!.Id;

        var context = new RequestContext();
        context.SignIn(aliceId);
        context.EnterOrganization(acme.Id, OrganizationRole.Owner);
        await using var db = CreateDb(context);

        db.Memberships.Add(new Membership
        {
            OrganizationId = globex.Id,
            UserId = aliceId,
            Role = OrganizationRole.Owner,
            CreatedAt = DateTimeOffset.UtcNow,
        });

        var error = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        var postgres = Assert.IsType<PostgresException>(error.InnerException);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, postgres.SqlState);
    }

    [Fact]
    public async Task Runtime_role_cannot_write_users_or_change_the_schema()
    {
        await using var connection = new NpgsqlConnection(api.AppConnectionString);
        await connection.OpenAsync();

        foreach (var sql in new[]
        {
            "INSERT INTO users (id, subject, created_at) VALUES (gen_random_uuid(), 'forged', now())",
            "ALTER TABLE organizations DISABLE ROW LEVEL SECURITY",
            "CREATE TABLE sneaky (id int)",
            "SELECT * FROM \"__EFMigrationsHistory\"",
        })
        {
            await using var command = new NpgsqlCommand(sql, connection);
            var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
            Assert.True(
                error.SqlState is PostgresErrorCodes.InsufficientPrivilege,
                $"Expected permission denied for: {sql}. Got {error.SqlState}: {error.MessageText}");
        }
    }

    // ---- Helpers ----------------------------------------------------------------------

    private async Task<(HttpClient Client, OrganizationResponse Organization)> SignUpWithOrganization(string person, string organization)
    {
        var client = api.ClientFor(TestUser.Create(person));
        var response = await client.PostAsJsonAsync("/api/organizations", new CreateOrganizationRequest(organization), Json.Options);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (client, (await response.Content.ReadFromJsonAsync<OrganizationResponse>(Json.Options))!);
    }

    private K9DbContext CreateDb(RequestContext context)
    {
        var options = new DbContextOptionsBuilder<K9DbContext>();
        K9DbContext.Configure(options, api.AppConnectionString);
        options.AddInterceptors(new TenantContextInterceptor(context));
        return new K9DbContext(options.Options);
    }
}
