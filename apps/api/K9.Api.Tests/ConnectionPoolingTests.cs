using System.Net;
using System.Net.Http.Json;
using K9.Api.Data;
using K9.Api.Organizations;
using K9.Api.Tenancy;
using K9.Api.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace K9.Api.Tests;

/// <summary>
/// Tenant context lives in Postgres session settings on pooled connections. These tests
/// prove it cannot leak from one request (or user) to the next.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class ConnectionPoolingTests(K9ApiFactory api)
{
    [Fact]
    public async Task Tenant_settings_are_cleared_when_a_connection_returns_to_the_pool()
    {
        // A one-connection pool guarantees the second open reuses the same physical connection.
        var connectionString = new NpgsqlConnectionStringBuilder(api.AppConnectionString)
        {
            MaxPoolSize = 1,
            ApplicationName = "k9-pool-probe",
        }.ConnectionString;

        var context = new RequestContext();
        context.SignIn(Guid.NewGuid());
        context.EnterOrganization(Guid.NewGuid(), OrganizationRole.Owner);

        int backendPid;
        await using (var db = CreateDb(context, connectionString))
        {
            await db.Database.OpenConnectionAsync();
            backendPid = await Scalar<int>(db, $"SELECT pg_backend_pid() AS \"Value\"");
            Assert.Equal(context.UserId.ToString(), await Scalar<string>(db, $"SELECT current_setting('k9.user_id', true) AS \"Value\""));
            await db.Database.CloseConnectionAsync();
        }

        // Same physical connection, opened without the interceptor, as any other code path would.
        await using var raw = new NpgsqlConnection(connectionString);
        await raw.OpenAsync();
        Assert.Equal(backendPid, await RawScalar<int>(raw, "SELECT pg_backend_pid()"));
        Assert.True(string.IsNullOrEmpty(await RawScalar<string?>(raw, "SELECT current_setting('k9.user_id', true)")));
        Assert.True(string.IsNullOrEmpty(await RawScalar<string?>(raw, "SELECT current_setting('k9.organization_id', true)")));
    }

    [Fact]
    public async Task Context_change_while_a_connection_is_open_is_applied_before_the_next_query()
    {
        var context = new RequestContext();
        context.SignIn(Guid.NewGuid());
        await using var db = CreateDb(context, api.AppConnectionString);

        await db.Database.OpenConnectionAsync();
        Assert.Equal("", await Scalar<string>(db, $"SELECT current_setting('k9.organization_id', true) AS \"Value\""));

        var organizationId = Guid.NewGuid();
        context.EnterOrganization(organizationId, OrganizationRole.Viewer);
        Assert.Equal(organizationId.ToString(), await Scalar<string>(db, $"SELECT current_setting('k9.organization_id', true) AS \"Value\""));
    }

    [Fact]
    public async Task Interleaved_concurrent_requests_from_two_tenants_never_see_each_other()
    {
        var (alice, acme) = await SignUpWithOrganization("Alice", "Acme");
        var (bob, globex) = await SignUpWithOrganization("Bob", "Globex");

        // Mix successes and failure paths (403, 404, 409, 400) so connections are returned
        // to the pool after errors too. The API's pool is small, so connections are reused.
        var requests = Enumerable.Range(0, 60).SelectMany(i => new Func<Task>[]
        {
            () => ExpectOnlyOrganization(alice, acme.Id),
            () => ExpectOnlyOrganization(bob, globex.Id),
            () => ExpectStatus(alice.GetAsync($"/api/organizations/{globex.Id}/members"), HttpStatusCode.Forbidden),
            () => ExpectStatus(bob.GetAsync($"/api/organizations/{acme.Id}"), HttpStatusCode.Forbidden),
            () => ExpectStatus(alice.PostAsJsonAsync($"/api/organizations/{acme.Id}/members", new AddMemberRequest($"nobody-{i}@k9.test", OrganizationRole.Viewer), Json.Options), HttpStatusCode.NotFound),
            () => ExpectStatus(bob.PostAsync($"/api/organizations/{globex.Id}/members", JsonContent("{not json")), HttpStatusCode.BadRequest),
            () => ExpectMembersOnlyFrom(bob, globex.Id),
        });

        // 16 in flight against a 4-connection pool: heavy reuse without starving the pool.
        using var gate = new SemaphoreSlim(16);
        await Task.WhenAll(requests.Select(async request =>
        {
            await gate.WaitAsync();
            try { await request(); }
            finally { gate.Release(); }
        }));
    }

    [Fact]
    public async Task Malformed_json_is_a_bad_request()
    {
        var (bob, globex) = await SignUpWithOrganization("Bob", "Globex");
        var response = await bob.PostAsync($"/api/organizations/{globex.Id}/members", JsonContent("{not json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static async Task ExpectOnlyOrganization(HttpClient client, Guid organizationId)
    {
        var me = await client.GetFromJsonAsync<MeResponse>("/api/me", Json.Options);
        Assert.Equal(organizationId, Assert.Single(me!.Organizations).Id);
    }

    private static async Task ExpectMembersOnlyFrom(HttpClient client, Guid organizationId)
    {
        var organization = await client.GetFromJsonAsync<OrganizationResponse>($"/api/organizations/{organizationId}", Json.Options);
        Assert.Equal(organizationId, organization!.Id);
        var members = await client.GetFromJsonAsync<List<MemberResponse>>($"/api/organizations/{organizationId}/members", Json.Options);
        Assert.Single(members!);
    }

    private static async Task ExpectStatus(Task<HttpResponseMessage> request, HttpStatusCode expected) =>
        Assert.Equal(expected, (await request).StatusCode);

    private static StringContent JsonContent(string body) => new(body, System.Text.Encoding.UTF8, "application/json");

    private async Task<(HttpClient Client, OrganizationResponse Organization)> SignUpWithOrganization(string person, string organization)
    {
        var client = api.ClientFor(TestUser.Create(person));
        var response = await client.PostAsJsonAsync("/api/organizations", new CreateOrganizationRequest(organization), Json.Options);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (client, (await response.Content.ReadFromJsonAsync<OrganizationResponse>(Json.Options))!);
    }

    private static K9DbContext CreateDb(RequestContext context, string connectionString)
    {
        var options = new DbContextOptionsBuilder<K9DbContext>();
        K9DbContext.Configure(options, connectionString);
        options.AddInterceptors(new TenantContextInterceptor(context));
        return new K9DbContext(options.Options);
    }

    private static Task<T> Scalar<T>(K9DbContext db, FormattableString sql) =>
        db.Database.SqlQuery<T>(sql).SingleAsync();

    private static async Task<T> RawScalar<T>(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        var value = await command.ExecuteScalarAsync();
        return value is null or DBNull ? default! : (T)value;
    }
}
