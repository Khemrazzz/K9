using System.Net;
using System.Net.Http.Json;
using K9.Api.Assessments;
using K9.Api.Tests.Infrastructure;
using static K9.Api.Tests.Infrastructure.ProwlerFixtures;

namespace K9.Api.Tests.Assessments;

/// <summary>
/// The invariant: the same set of valid observations always yields the same findings,
/// whatever the import order, concurrency or failures along the way.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class AssessmentConcurrencyTests(K9ApiFactory api)
{
    private async Task<(Actor Analyst, Guid Organization)> NewOrganizationAsync()
    {
        var owner = await api.SignInAsync("Owner");
        return (owner, await owner.CreateOrganizationAsync());
    }

    [Fact]
    public async Task Concurrent_imports_reach_the_same_state_as_sequential_ones_in_either_order()
    {
        string[] scans = [BaselineA, FollowupA, ThirdA];

        var (forward, forwardOrg) = await NewOrganizationAsync();
        foreach (var scan in scans)
        {
            await forward.ImportCreatedAsync(forwardOrg, scan);
        }
        var (backward, backwardOrg) = await NewOrganizationAsync();
        foreach (var scan in scans.Reverse())
        {
            await backward.ImportCreatedAsync(backwardOrg, scan);
        }
        var expected = await forward.SnapshotAsync(forwardOrg);
        Assert.Equal(expected, await backward.SnapshotAsync(backwardOrg));

        for (var round = 0; round < 4; round++)
        {
            var (analyst, org) = await NewOrganizationAsync();
            var ordered = round % 2 == 0 ? scans : scans.Reverse().ToArray();
            var responses = await Task.WhenAll(ordered.Select(scan => analyst.ImportAsync(org, scan)));

            Assert.All(responses, r => Assert.Equal(HttpStatusCode.Created, r.StatusCode));
            Assert.Equal(expected, await analyst.SnapshotAsync(org));
        }
    }

    [Fact]
    public async Task Overlapping_concurrent_imports_record_each_observation_once()
    {
        for (var round = 0; round < 3; round++)
        {
            var (analyst, org) = await NewOrganizationAsync();
            var responses = await Task.WhenAll(analyst.ImportAsync(org, FollowupA), analyst.ImportAsync(org, ReexportA));

            Assert.All(responses, r => Assert.Equal(HttpStatusCode.Created, r.StatusCode));
            var imports = await Task.WhenAll(responses.Select(r => r.Content.ReadFromJsonAsync<ImportResponse>(Json.Options)));
            Assert.Equal(9, imports.Sum(i => i!.Observations.Recorded));
            Assert.Equal(9, imports.Sum(i => i!.Observations.AlreadyKnown));
            Assert.Equal(9, (await api.RowCountsAsync(org)).Observations);
        }
    }

    [Fact]
    public async Task Of_two_concurrent_contradicting_imports_exactly_one_wins_and_the_state_matches_it()
    {
        for (var round = 0; round < 3; round++)
        {
            var (analyst, org) = await NewOrganizationAsync();
            var pass = analyst.ImportAsync(org, FollowupA); // k9-logs PASS at T2
            var fail = analyst.ImportAsync(org, ConflictA); // k9-logs FAIL at T2
            await Task.WhenAll(pass, fail);

            var statuses = new[] { (await pass).StatusCode, (await fail).StatusCode };
            Assert.Single(statuses, HttpStatusCode.Created);
            Assert.Single(statuses, HttpStatusCode.Conflict);

            var logs = (await analyst.FindingsAsync(org)).Where(f => f.ResourceName == "k9-logs").ToList();
            if ((await pass).StatusCode == HttpStatusCode.Created)
            {
                Assert.Empty(logs); // a PASS baseline only
                Assert.Equal(9, (await api.RowCountsAsync(org)).Observations);
            }
            else
            {
                Assert.Equal(FindingStatus.Open, Assert.Single(logs).Status);
                Assert.Equal(1, (await api.RowCountsAsync(org)).Observations);
            }
        }
    }

    [Fact]
    public async Task A_failure_while_updating_findings_rolls_back_the_entire_import()
    {
        var (analyst, org) = await NewOrganizationAsync();
        await analyst.ImportCreatedAsync(org, BaselineA);
        var before = await api.RowCountsAsync(org);
        var snapshot = await analyst.SnapshotAsync(org);

        await InjectProjectionFailureAsync(org);
        try
        {
            var response = await analyst.ImportAsync(org, FollowupA);
            Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
            Assert.Equal(before, await api.RowCountsAsync(org));
            Assert.Equal(snapshot, await analyst.SnapshotAsync(org));
        }
        finally
        {
            await RemoveProjectionFailureAsync();
        }

        // Nothing of the failed attempt lingers: the same file is not a "duplicate" now.
        var retried = await analyst.ImportCreatedAsync(org, FollowupA);
        Assert.False(retried.Duplicate);
        Assert.Equal(9, retried.Observations.Recorded);
    }

    [Fact]
    public async Task A_failed_first_import_leaves_an_organization_with_no_assessment_data()
    {
        var (analyst, org) = await NewOrganizationAsync();
        await InjectProjectionFailureAsync(org);
        try
        {
            var response = await analyst.ImportAsync(org, BaselineA);
            Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
            Assert.Equal(new AssessmentRowCounts(0, 0, 0, 0), await api.RowCountsAsync(org));
            Assert.Empty(await analyst.FindingsAsync(org));
            Assert.Empty(await analyst.ImportHistoryAsync(org));
        }
        finally
        {
            await RemoveProjectionFailureAsync();
        }
    }

    // A trigger, installed as the superuser for this test only, that fails any write of this
    // organization's findings: the last step of an import, after its observations are written.
    private Task InjectProjectionFailureAsync(Guid organizationId) =>
        Scenario.ExecuteAsync(api.SuperuserConnectionString, $"""
            CREATE FUNCTION public.k9_test_fail_projection() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.organization_id = '{organizationId}' THEN
                    RAISE EXCEPTION 'injected projection failure';
                END IF;
                RETURN NEW;
            END $$;
            CREATE TRIGGER k9_test_fail_projection BEFORE INSERT OR UPDATE ON public.findings
                FOR EACH ROW EXECUTE FUNCTION public.k9_test_fail_projection();
            """);

    private Task RemoveProjectionFailureAsync() =>
        Scenario.ExecuteAsync(api.SuperuserConnectionString, """
            DROP TRIGGER IF EXISTS k9_test_fail_projection ON public.findings;
            DROP FUNCTION IF EXISTS public.k9_test_fail_projection();
            """);
}
