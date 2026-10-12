using System.Net;
using K9.Api.Organizations;
using K9.Api.Tests.Infrastructure;
using Npgsql;
using static K9.Api.Tests.Infrastructure.ProwlerFixtures;

namespace K9.Api.Tests.Assessments;

/// <summary>Tenant isolation, roles, immutable history and the per-account import lock.</summary>
[Collection(ApiCollection.Name)]
public sealed class AssessmentIsolationTests(K9ApiFactory api)
{
    private static readonly string[] HistoryTables = ["assessment_imports", "finding_observations"];
    private static readonly string[] AssessmentTables = ["assessment_imports", "finding_observations", "findings"];

    // ---- Roles and tenants over HTTP ---------------------------------------------------

    [Fact]
    public async Task Analysts_can_import_viewers_can_only_read_and_outsiders_get_nothing()
    {
        var owner = await api.SignInAsync("Owner");
        var analyst = await api.SignInAsync("Analyst");
        var viewer = await api.SignInAsync("Viewer");
        var outsider = await api.SignInAsync("Outsider");
        var org = await owner.CreateOrganizationAsync();
        await owner.AddMemberAsync(org, analyst, OrganizationRole.Analyst);
        await owner.AddMemberAsync(org, viewer, OrganizationRole.Viewer);
        await outsider.CreateOrganizationAsync();

        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.ImportAsync(org, BaselineA)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await outsider.ImportAsync(org, BaselineA)).StatusCode);
        Assert.Equal(new AssessmentRowCounts(0, 0, 0, 0), await api.RowCountsAsync(org));

        await analyst.ImportCreatedAsync(org, BaselineA);
        var finding = (await viewer.FindingsAsync(org)).First();
        await viewer.FindingAsync(org, finding.Id);
        await viewer.ImportHistoryAsync(org);

        foreach (var path in new[] { "findings", $"findings/{finding.Id}", "assessments/imports" })
        {
            Assert.Equal(HttpStatusCode.Forbidden, (await outsider.Client.GetAsync($"/api/organizations/{org}/{path}")).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await api.CreateClient().GetAsync($"/api/organizations/{org}/{path}")).StatusCode);
        }
    }

    [Fact]
    public async Task A_finding_cannot_be_reached_through_another_organizations_route()
    {
        var alice = await api.SignInAsync("Alice");
        var acme = await alice.CreateOrganizationAsync("Acme");
        var other = await alice.CreateOrganizationAsync("Other");
        await alice.ImportCreatedAsync(acme, BaselineA);
        var finding = (await alice.FindingsAsync(acme)).First();

        // Alice belongs to both, so authorization passes; the finding still belongs to Acme only.
        var response = await alice.Client.GetAsync($"/api/organizations/{other}/findings/{finding.Id}");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(await alice.FindingsAsync(other));
    }

    [Fact]
    public async Task The_same_file_imported_by_two_organizations_is_two_independent_imports()
    {
        var alice = await api.SignInAsync("Alice");
        var bob = await api.SignInAsync("Bob");
        var acme = await alice.CreateOrganizationAsync("Acme");
        var globex = await bob.CreateOrganizationAsync("Globex");

        var first = await alice.ImportCreatedAsync(acme, BaselineA);
        var second = await bob.ImportCreatedAsync(globex, BaselineA);

        Assert.False(second.Duplicate);
        Assert.NotEqual(first.Id, second.Id);
        Assert.Equal(first.FileSha256, second.FileSha256);
        Assert.Equal(await alice.SnapshotAsync(acme), await bob.SnapshotAsync(globex));
        var acmeIds = (await alice.FindingsAsync(acme)).Select(f => f.Id).ToHashSet();
        Assert.DoesNotContain(await bob.FindingsAsync(globex), f => acmeIds.Contains(f.Id));
    }

    // ---- Row-level security ------------------------------------------------------------

    [Fact]
    public async Task The_database_returns_only_the_active_organizations_rows_even_without_filters()
    {
        var alice = await api.SignInAsync("Alice");
        var bob = await api.SignInAsync("Bob");
        var acme = await alice.CreateOrganizationAsync("Acme");
        var globex = await bob.CreateOrganizationAsync("Globex");
        await alice.ImportCreatedAsync(acme, BaselineA);
        await bob.ImportCreatedAsync(globex, BaselineB);

        foreach (var table in AssessmentTables)
        {
            var asAcme = await AppScalarAsync<long>(alice.Id, acme, $"SELECT count(*) FROM {table} WHERE organization_id <> '{acme}'");
            Assert.Equal(0, asAcme);
            Assert.True(await AppScalarAsync<long>(alice.Id, acme, $"SELECT count(*) FROM {table}") > 0, table);
            Assert.Equal(0, await AppScalarAsync<long>(null, null, $"SELECT count(*) FROM {table}"));
        }
    }

    [Fact]
    public async Task The_runtime_role_cannot_write_into_another_organization()
    {
        var alice = await api.SignInAsync("Alice");
        var bob = await api.SignInAsync("Bob");
        var acme = await alice.CreateOrganizationAsync("Acme");
        var globex = await bob.CreateOrganizationAsync("Globex");
        await bob.ImportCreatedAsync(globex, BaselineB);

        // Row-level security is checked before NOT NULL and other constraints, so a row that
        // claims another organization fails on that alone, whatever else it lacks.
        foreach (var table in AssessmentTables)
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => AppExecuteAsync(alice.Id, acme,
                $"INSERT INTO {table} (organization_id) VALUES ('{globex}')"));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        }

        // Globex's findings are invisible to Acme, so an update cannot reach them either.
        var before = await api.RowCountsAsync(globex);
        try
        {
            var moved = await AppScalarAsync<long>(alice.Id, acme,
                $"WITH changed AS (UPDATE findings SET organization_id = '{acme}' RETURNING 1) SELECT count(*) FROM changed");
            Assert.Equal(0, moved);
        }
        catch (PostgresException error) when (error.SqlState == PostgresErrorCodes.InsufficientPrivilege)
        {
            // Also fine: the runtime role may not update that column at all.
        }
        Assert.Equal(before, await api.RowCountsAsync(globex));
    }

    [Fact]
    public async Task Observation_and_import_history_is_append_only()
    {
        var alice = await api.SignInAsync("Alice");
        var acme = await alice.CreateOrganizationAsync();
        await alice.ImportCreatedAsync(acme, BaselineA);

        foreach (var table in HistoryTables)
        {
            foreach (var sql in new[] { $"UPDATE {table} SET organization_id = organization_id", $"DELETE FROM {table}", $"TRUNCATE {table}" })
            {
                var asApp = await Assert.ThrowsAsync<PostgresException>(() => AppExecuteAsync(alice.Id, acme, sql));
                Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, asApp.SqlState);

                var asOwner = await Assert.ThrowsAsync<PostgresException>(() => Scenario.ExecuteAsync(api.OwnerConnectionString, sql));
                Assert.Contains("append-only", asOwner.MessageText);
            }
        }

        // Findings are a projection the importer maintains, but never deletes.
        foreach (var sql in new[] { "DELETE FROM findings", "TRUNCATE findings" })
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => AppExecuteAsync(alice.Id, acme, sql));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        }
        Assert.Equal(10, (await api.RowCountsAsync(acme)).Observations);
    }

    // ---- The per-account import lock -------------------------------------------------

    [Fact]
    public async Task An_import_waits_for_the_lock_of_each_account_it_touches()
    {
        var alice = await api.SignInAsync("Alice");
        var acme = await alice.CreateOrganizationAsync();

        await using var holder = new NpgsqlConnection(api.SuperuserConnectionString);
        await holder.OpenAsync();
        await using (var take = new NpgsqlCommand($"SELECT pg_advisory_lock(k9_assessment_lock_key('{acme}', 'aws', '{AccountB}'))", holder))
        {
            await take.ExecuteNonQueryAsync();
        }

        var import = alice.ImportAsync(acme, MultiAccount);
        await Task.Delay(TimeSpan.FromSeconds(2));
        Assert.False(import.IsCompleted, "the import did not wait for account B's lock");

        await using (var release = new NpgsqlCommand("SELECT pg_advisory_unlock_all()", holder))
        {
            await release.ExecuteNonQueryAsync();
        }
        Assert.Equal(HttpStatusCode.Created, (await import.WaitAsync(TimeSpan.FromSeconds(30))).StatusCode);
    }

    [Fact]
    public async Task Colliding_lock_keys_only_serialize_imports_and_never_mix_tenants()
    {
        const string Function = "k9_assessment_lock_key(uuid, text, text)";
        var original = await AssessmentScenario.ScalarAsync<string>(api.SuperuserConnectionString, $"SELECT pg_get_functiondef('{Function}'::regprocedure)");
        // Every organization and account now shares one lock.
        await Scenario.ExecuteAsync(api.SuperuserConnectionString,
            "CREATE OR REPLACE FUNCTION public.k9_assessment_lock_key(uuid, text, text) RETURNS bigint LANGUAGE sql IMMUTABLE AS $$ SELECT 42::bigint $$");
        try
        {
            var actors = new List<(Actor Actor, Guid Org, string Fixture)>();
            foreach (var (name, fixture) in new[] { ("Alice", BaselineA), ("Bob", BaselineB), ("Carol", MultiAccount), ("Dave", FollowupA) })
            {
                var actor = await api.SignInAsync(name);
                actors.Add((actor, await actor.CreateOrganizationAsync(name), fixture));
            }

            var responses = await Task.WhenAll(actors.Select(a => a.Actor.ImportAsync(a.Org, a.Fixture)));
            Assert.All(responses, r => Assert.Equal(HttpStatusCode.Created, r.StatusCode));

            foreach (var (actor, org, fixture) in actors)
            {
                var expectedAccounts = (await ReadValidAsync(fixture)).Select(o => o.AccountUid).ToHashSet();
                var findings = await actor.FindingsAsync(org);
                Assert.All(findings, f => Assert.Contains(f.AccountUid, expectedAccounts));
                Assert.Equal((long)(await ReadValidAsync(fixture)).Count, (await api.RowCountsAsync(org)).Observations);
            }
        }
        finally
        {
            await Scenario.ExecuteAsync(api.SuperuserConnectionString, original!);
        }
    }

    // ---- Helpers -------------------------------------------------------------------------

    private async Task<T> AppScalarAsync<T>(Guid? userId, Guid? organizationId, string sql)
    {
        await using var connection = new NpgsqlConnection(api.AppConnectionString);
        await connection.OpenAsync();
        await SetContextAsync(connection, userId, organizationId);
        await using var command = new NpgsqlCommand(sql, connection);
        return (T)(await command.ExecuteScalarAsync())!;
    }

    private async Task AppExecuteAsync(Guid? userId, Guid? organizationId, string sql)
    {
        await using var connection = new NpgsqlConnection(api.AppConnectionString);
        await connection.OpenAsync();
        await SetContextAsync(connection, userId, organizationId);
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task SetContextAsync(NpgsqlConnection connection, Guid? userId, Guid? organizationId)
    {
        await using var command = new NpgsqlCommand(
            "SELECT set_config('k9.user_id', @u, false), set_config('k9.organization_id', @o, false)", connection);
        command.Parameters.AddWithValue("u", userId?.ToString() ?? "");
        command.Parameters.AddWithValue("o", organizationId?.ToString() ?? "");
        await command.ExecuteNonQueryAsync();
    }
}
