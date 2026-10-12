using System.Net;
using System.Net.Http.Json;
using K9.Api.Audit;
using K9.Api.Data;
using K9.Api.Organizations;
using K9.Api.Tenancy;
using K9.Api.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace K9.Api.Tests;

[Collection(ApiCollection.Name)]
public sealed class AuditTests(K9ApiFactory api)
{
    // ---- What gets recorded ------------------------------------------------------------

    [Fact]
    public async Task Organization_creation_is_recorded_with_the_verified_actor_and_server_correlation_id()
    {
        var alice = await api.SignInAsync("Alice");
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/organizations")
        {
            Content = JsonContent.Create(new CreateOrganizationRequest("Acme"), options: Json.Options),
        };
        request.Headers.Add(CorrelationId.HeaderName, "spoofed-by-client");
        request.Headers.Add("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01");
        var response = await alice.Client.SendAsync(request);
        var organizationId = (await response.Content.ReadFromJsonAsync<OrganizationResponse>(Json.Options))!.Id;

        var correlationId = Scenario.CorrelationIdOf(response);
        Assert.NotEqual("spoofed-by-client", correlationId);
        Assert.Matches("^[0-9a-f]{32}$", correlationId);

        var created = Assert.Single((await alice.AuditAsync(organizationId, "?action=organization.create")).Items);
        Assert.Equal("success", created.Outcome);
        Assert.Equal(alice.Id, created.ActorUserId);
        Assert.Equal(alice.User.Email, created.ActorEmail);
        Assert.Equal(correlationId, created.CorrelationId);
        Assert.Equal(organizationId.ToString(), created.ResourceId);
        Assert.InRange(created.OccurredAt, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
    }

    [Fact]
    public async Task Membership_changes_are_recorded_with_roles_before_and_after()
    {
        var owner = await api.SignInAsync("Owner");
        var member = await api.SignInAsync("Member");
        var organizationId = await owner.CreateOrganizationAsync();

        Assert.Equal(HttpStatusCode.Created, (await owner.AddMemberAsync(organizationId, member, OrganizationRole.Viewer)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await owner.ChangeRoleAsync(organizationId, member.Id, OrganizationRole.Analyst)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.RemoveMemberAsync(organizationId, member.Id)).StatusCode);

        var events = (await owner.AuditAsync(organizationId, "?outcome=success")).Items
            .Where(e => e.Action.StartsWith("membership.", StringComparison.Ordinal))
            .ToDictionary(e => e.Action);

        Assert.Equal("Viewer", events[AuditActions.MembershipAdd].Details!.Value.GetProperty("role").GetString());
        var changed = events[AuditActions.MembershipChangeRole].Details!.Value;
        Assert.Equal("Viewer", changed.GetProperty("previous_role").GetString());
        Assert.Equal("Analyst", changed.GetProperty("role").GetString());
        Assert.Equal("Analyst", events[AuditActions.MembershipRemove].Details!.Value.GetProperty("role").GetString());
        Assert.All(events.Values, e =>
        {
            Assert.Equal(member.Id.ToString(), e.ResourceId);
            Assert.Equal(owner.Id, e.ActorUserId);
        });
    }

    [Fact]
    public async Task A_members_denied_action_is_recorded_in_their_organizations_log()
    {
        var owner = await api.SignInAsync("Owner");
        var viewer = await api.SignInAsync("Viewer");
        var organizationId = await owner.CreateOrganizationAsync();
        await owner.AddMemberAsync(organizationId, viewer, OrganizationRole.Viewer);

        var attempt = await viewer.AddMemberAsync(organizationId, owner, OrganizationRole.Owner);
        Assert.Equal(HttpStatusCode.Forbidden, attempt.StatusCode);

        var denied = Assert.Single((await owner.AuditAsync(organizationId, "?outcome=denied")).Items);
        Assert.Equal(AuditActions.OrganizationAccess, denied.Action);
        Assert.Equal(viewer.Id, denied.ActorUserId);
        Assert.Equal(Scenario.CorrelationIdOf(attempt), denied.CorrelationId);
        Assert.Equal("Admin", denied.Details!.Value.GetProperty("required_role").GetString());
        Assert.Equal("Viewer", denied.Details!.Value.GetProperty("held_role").GetString());
    }

    [Fact]
    public async Task An_outsiders_attempt_is_recorded_platform_side_but_cannot_write_into_the_tenants_log()
    {
        var owner = await api.SignInAsync("Owner");
        var mallory = await api.SignInAsync("Mallory");
        var organizationId = await owner.CreateOrganizationAsync();

        var attempt = await mallory.Client.GetAsync($"/api/organizations/{organizationId}/members");
        Assert.Equal(HttpStatusCode.Forbidden, attempt.StatusCode);

        var row = Assert.Single(await api.AuditRowsAsync(Scenario.CorrelationIdOf(attempt)));
        Assert.Equal(AuditActions.OrganizationAccess, row["action"]);
        Assert.Equal("denied", row["outcome"]);
        Assert.Equal(mallory.Id, row["actor_user_id"]);
        Assert.Null(row["organization_id"]);
        Assert.Equal(organizationId.ToString(), row["resource_id"]);

        var tenantLog = (await owner.AuditAsync(organizationId)).Items;
        Assert.DoesNotContain(tenantLog, e => e.ActorUserId == mallory.Id);
    }

    [Fact]
    public async Task Refused_role_grants_are_recorded_with_the_reason()
    {
        var owner = await api.SignInAsync("Owner");
        var admin = await api.SignInAsync("Admin");
        var newcomer = await api.SignInAsync("Newcomer");
        var organizationId = await owner.CreateOrganizationAsync();
        await owner.AddMemberAsync(organizationId, admin, OrganizationRole.Admin);

        var attempt = await admin.AddMemberAsync(organizationId, newcomer, OrganizationRole.Owner);
        Assert.Equal(HttpStatusCode.Forbidden, attempt.StatusCode);

        var denied = Assert.Single((await owner.AuditAsync(organizationId, "?action=membership.add&outcome=denied")).Items);
        Assert.Equal(admin.Id, denied.ActorUserId);
        Assert.Equal("role_above_own", denied.Details!.Value.GetProperty("reason").GetString());
    }

    public static TheoryData<string, Func<TestUser, string>> RejectedTokens => new()
    {
        { "invalid_audience", u => TestTokens.For(u, audience: "some-other-api") },
        { "expired", u => TestTokens.For(u, lifetime: TimeSpan.FromMinutes(-5)) },
        { "invalid_signature", u => TestTokens.For(u, key: TestTokens.UntrustedKey) },
        { "wrong_token_type", u => TestTokens.For(u, tokenType: "Refresh") },
        { "malformed", _ => "definitely-not-a-jwt" },
    };

    [Theory]
    [MemberData(nameof(RejectedTokens))]
    public async Task Rejected_tokens_are_recorded_without_any_token_material(string reason, Func<TestUser, string> token)
    {
        var user = TestUser.Create("Mallory");
        var presented = token(user);
        var response = await api.ClientWithToken(presented).GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var row = Assert.Single(await api.AuditRowsAsync(Scenario.CorrelationIdOf(response)));
        Assert.Equal(AuditActions.TokenRejected, row["action"]);
        Assert.Equal("failure", row["outcome"]);
        Assert.Contains($"\"reason\": \"{reason}\"", (string)row["details"]!);
        Assert.Null(row["actor_user_id"]);

        var raw = (string)row["raw"]!;
        Assert.DoesNotContain(presented, raw);
        foreach (var segment in presented.Split('.').Where(s => s.Length > 8))
        {
            Assert.DoesNotContain(segment, raw);
        }
        Assert.DoesNotContain(user.Subject, raw);
        Assert.DoesNotContain(user.Email, raw);
    }

    // ---- Who can read it --------------------------------------------------------------

    [Fact]
    public async Task Only_admins_of_the_organization_can_read_its_audit_log()
    {
        var owner = await api.SignInAsync("Owner");
        var analyst = await api.SignInAsync("Analyst");
        var otherOwner = await api.SignInAsync("OtherOwner");
        var organizationId = await owner.CreateOrganizationAsync();
        await otherOwner.CreateOrganizationAsync();
        await owner.AddMemberAsync(organizationId, analyst, OrganizationRole.Analyst);

        Assert.Equal(HttpStatusCode.Forbidden, (await analyst.Client.GetAsync($"/api/organizations/{organizationId}/audit-events")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await otherOwner.Client.GetAsync($"/api/organizations/{organizationId}/audit-events")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await api.CreateClient().GetAsync($"/api/organizations/{organizationId}/audit-events")).StatusCode);
    }

    [Fact]
    public async Task Each_organization_sees_only_its_own_events_even_without_api_filters()
    {
        var alice = await api.SignInAsync("Alice");
        var bob = await api.SignInAsync("Bob");
        var acme = await alice.CreateOrganizationAsync("Acme");
        var globex = await bob.CreateOrganizationAsync("Globex");

        Assert.DoesNotContain((await alice.AuditAsync(acme)).Items, e => e.ActorUserId == bob.Id);

        var context = new RequestContext();
        context.SignIn(alice.Id);
        context.EnterOrganization(acme, OrganizationRole.Owner);
        await using (var db = CreateDb(context))
        {
            var organizations = await db.AuditEvents.Select(e => e.OrganizationId).Distinct().ToListAsync();
            Assert.Equal(new Guid?[] { acme }, organizations);
        }

        await using (var anonymous = CreateDb(new RequestContext()))
        {
            Assert.Empty(await anonymous.AuditEvents.ToListAsync());
        }
        Assert.NotEqual(acme, globex);
    }

    [Fact]
    public async Task Pages_are_newest_first_complete_and_stable_while_new_events_arrive()
    {
        var owner = await api.SignInAsync("Owner");
        var organizationId = await owner.CreateOrganizationAsync();
        for (var i = 0; i < 5; i++)
        {
            await owner.AddMemberAsync(organizationId, await api.SignInAsync($"Member{i}"), OrganizationRole.Viewer);
        }

        var snapshot = (await owner.AuditAsync(organizationId, "?limit=200")).Items.Select(e => e.Id).ToList();

        var paged = new List<long>();
        long? cursor = null;
        do
        {
            // Every read adds an audit.read event; keyset paging must not shift because of it.
            var page = await owner.AuditAsync(organizationId, $"?limit=2{(cursor is null ? "" : $"&before={cursor}")}");
            Assert.True(page.Items.Count <= 2);
            paged.AddRange(page.Items.Select(e => e.Id));
            cursor = page.NextCursor;
        }
        while (cursor is not null);

        var comparable = paged.Where(id => id <= snapshot[0]).ToList();
        Assert.Equal(snapshot, comparable);
        Assert.Equal(paged.OrderByDescending(id => id), paged);
        Assert.Equal(paged.Count, paged.Distinct().Count());
    }

    [Fact]
    public async Task Filters_narrow_results()
    {
        var owner = await api.SignInAsync("Owner");
        var admin = await api.SignInAsync("Admin");
        var viewer = await api.SignInAsync("Viewer");
        var organizationId = await owner.CreateOrganizationAsync();
        await owner.AddMemberAsync(organizationId, admin, OrganizationRole.Admin);
        await admin.AddMemberAsync(organizationId, viewer, OrganizationRole.Viewer);

        var byAdmin = (await owner.AuditAsync(organizationId, $"?actorUserId={admin.Id}&action=membership.add")).Items;
        var single = Assert.Single(byAdmin);
        Assert.Equal(viewer.Id.ToString(), single.ResourceId);

        var future = Uri.EscapeDataString(DateTimeOffset.UtcNow.AddHours(1).ToString("O"));
        Assert.Empty((await owner.AuditAsync(organizationId, $"?from={future}")).Items);
    }

    public static TheoryData<string> MalformedQueries => new()
    {
        "?limit=0",
        "?limit=201",
        "?limit=-1",
        "?before=0",
        "?before=abc",
        "?action=DROP%20TABLE%20audit_events",
        "?action=membership",
        "?action=" + new string('a', 30) + "." + new string('b', 40),
        "?outcome=maybe",
        "?actorUserId=not-a-guid",
        "?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z",
        "?from=yesterday",
    };

    [Theory]
    [MemberData(nameof(MalformedQueries))]
    public async Task Malformed_queries_are_rejected(string query)
    {
        var owner = await api.SignInAsync("Owner");
        var organizationId = await owner.CreateOrganizationAsync();
        var response = await owner.Client.GetAsync($"/api/organizations/{organizationId}/audit-events{query}");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---- Integrity -----------------------------------------------------------------------

    [Fact]
    public async Task History_cannot_be_changed_by_the_runtime_role_or_casually_by_the_owner()
    {
        var owner = await api.SignInAsync("Owner");
        var organizationId = await owner.CreateOrganizationAsync();

        foreach (var sql in new[]
        {
            $"SELECT set_config('k9.organization_id', '{organizationId}', false); UPDATE audit_events SET outcome = 'success'",
            $"SELECT set_config('k9.organization_id', '{organizationId}', false); DELETE FROM audit_events",
            "TRUNCATE audit_events",
            "INSERT INTO audit_events (action, outcome, correlation_id) VALUES ('organization.create', 'success', 'forged')",
        })
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => Scenario.ExecuteAsync(api.AppConnectionString, sql));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        }

        foreach (var sql in new[] { "UPDATE audit_events SET outcome = 'success'", "DELETE FROM audit_events", "TRUNCATE audit_events" })
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => Scenario.ExecuteAsync(api.OwnerConnectionString, sql));
            Assert.Contains("append-only", error.MessageText);
        }

        Assert.NotEmpty((await owner.AuditAsync(organizationId)).Items);
    }

    public static TheoryData<string, string> SpoofedOrMalformedWrites => new()
    {
        // Claiming another organization's log for a success.
        { "SELECT k9_record_audit_event('organization.create', 'success', '{other}', NULL, NULL, 'c1', NULL, NULL)", PostgresErrorCodes.InsufficientPrivilege },
        // A denial may name only an organization the actor belongs to.
        { "SELECT k9_record_audit_event('authz.organization_access', 'denied', '{other}', NULL, NULL, 'c1', NULL, NULL)", PostgresErrorCodes.InsufficientPrivilege },
        { "SELECT k9_record_audit_event('Bad Action', 'success', NULL, NULL, NULL, 'c1', NULL, NULL)", PostgresErrorCodes.InvalidParameterValue },
        { "SELECT k9_record_audit_event('a.b', 'maybe', NULL, NULL, NULL, 'c1', NULL, NULL)", PostgresErrorCodes.InvalidParameterValue },
        { "SELECT k9_record_audit_event('a.b', 'success', NULL, 'Bad Type', NULL, 'c1', NULL, NULL)", PostgresErrorCodes.InvalidParameterValue },
        { "SELECT k9_record_audit_event('a.b', 'success', NULL, NULL, E'line\\nbreak', 'c1', NULL, NULL)", PostgresErrorCodes.InvalidParameterValue },
        { "SELECT k9_record_audit_event('a.b', 'success', NULL, NULL, NULL, 'not a correlation id', NULL, NULL)", PostgresErrorCodes.InvalidParameterValue },
        { "SELECT k9_record_audit_event('a.b', 'success', NULL, NULL, NULL, 'c1', NULL, '[1,2]')", PostgresErrorCodes.InvalidParameterValue },
        { "SELECT k9_record_audit_event('a.b', 'success', NULL, NULL, NULL, 'c1', NULL, jsonb_build_object('x', repeat('y', 5000)))", PostgresErrorCodes.InvalidParameterValue },
    };

    [Theory]
    [MemberData(nameof(SpoofedOrMalformedWrites))]
    public async Task The_write_function_rejects_spoofed_and_malformed_events(string sql, string expectedState)
    {
        var alice = await api.SignInAsync("Alice");
        var bob = await api.SignInAsync("Bob");
        var acme = await alice.CreateOrganizationAsync();
        var globex = await bob.CreateOrganizationAsync();

        var withContext = $"SELECT set_config('k9.user_id', '{alice.Id}', false), set_config('k9.organization_id', '{acme}', false); "
            + sql.Replace("{other}", globex.ToString());
        var error = await Assert.ThrowsAsync<PostgresException>(() => Scenario.ExecuteAsync(api.AppConnectionString, withContext));
        Assert.Equal(expectedState, error.SqlState);
    }

    [Fact]
    public async Task The_actor_is_always_the_session_user_never_a_parameter()
    {
        var alice = await api.SignInAsync("Alice");
        var acme = await alice.CreateOrganizationAsync();

        await using var connection = new NpgsqlConnection(api.AppConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            $"SELECT set_config('k9.user_id', '{alice.Id}', false), set_config('k9.organization_id', '{acme}', false); " +
            "SELECT k9_record_audit_event('organization.create', 'success', NULL, NULL, NULL, 'actor-check', NULL, NULL)", connection);
        await command.ExecuteNonQueryAsync();

        var row = Assert.Single(await api.AuditRowsAsync("actor-check"));
        Assert.Equal(alice.Id, row["actor_user_id"]);
    }

    // ---- Audit storage unavailable ---------------------------------------------------

    [Fact]
    public async Task Security_changes_fail_closed_when_the_audit_log_is_unavailable()
    {
        var owner = await api.SignInAsync("Owner");
        var member = await api.SignInAsync("Member");
        var mallory = await api.SignInAsync("Mallory");
        var organizationId = await owner.CreateOrganizationAsync();
        await owner.AddMemberAsync(organizationId, member, OrganizationRole.Viewer);
        var newcomer = await api.SignInAsync("Newcomer");

        const string Function = "k9_record_audit_event(text, text, uuid, text, text, text, inet, jsonb)";
        await Scenario.ExecuteAsync(api.SuperuserConnectionString, $"REVOKE EXECUTE ON FUNCTION {Function} FROM k9_app");
        try
        {
            // Changes are refused and nothing is written.
            var create = await owner.Client.PostAsJsonAsync("/api/organizations", new CreateOrganizationRequest("Unaudited"), Json.Options);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, create.StatusCode);
            var add = await owner.AddMemberAsync(organizationId, newcomer, OrganizationRole.Viewer);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, add.StatusCode);
            var change = await owner.ChangeRoleAsync(organizationId, member.Id, OrganizationRole.Admin);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, change.StatusCode);
            var remove = await owner.RemoveMemberAsync(organizationId, member.Id);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, remove.StatusCode);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, (await owner.Client.GetAsync($"/api/organizations/{organizationId}/audit-events")).StatusCode);

            // Refusals stay refusals.
            Assert.Equal(HttpStatusCode.Forbidden, (await mallory.Client.GetAsync($"/api/organizations/{organizationId}")).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await api.ClientWithToken("garbage").GetAsync("/api/me")).StatusCode);

            // Plain reads are not audited and keep working.
            var me = await owner.Client.GetFromJsonAsync<MeResponse>("/api/me", Json.Options);
            Assert.DoesNotContain(me!.Organizations, o => o.Name == "Unaudited");
            var members = await owner.Client.GetFromJsonAsync<List<MemberResponse>>($"/api/organizations/{organizationId}/members", Json.Options);
            Assert.Equal(2, members!.Count);
            Assert.Equal(OrganizationRole.Viewer, members.Single(m => m.UserId == member.Id).Role);
        }
        finally
        {
            await Scenario.ExecuteAsync(api.SuperuserConnectionString, $"GRANT EXECUTE ON FUNCTION {Function} TO k9_app");
        }
    }

    private K9DbContext CreateDb(RequestContext context)
    {
        var options = new DbContextOptionsBuilder<K9DbContext>();
        K9DbContext.Configure(options, api.AppConnectionString);
        options.AddInterceptors(new TenantContextInterceptor(context));
        return new K9DbContext(options.Options);
    }
}
