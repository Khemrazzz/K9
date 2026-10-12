using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using K9.Api.Assessments;
using K9.Api.Tests.Infrastructure;
using static K9.Api.Tests.Infrastructure.ProwlerFixtures;

namespace K9.Api.Tests.Assessments;

/// <summary>Importing Prowler scans through the API, and the findings that result.</summary>
[Collection(ApiCollection.Name)]
public sealed class AssessmentImportTests(K9ApiFactory api)
{
    private async Task<(Actor Analyst, Guid Organization)> NewOrganizationAsync()
    {
        var owner = await api.SignInAsync("Owner");
        return (owner, await owner.CreateOrganizationAsync());
    }

    // ---- Lifecycle through imports -----------------------------------------------------

    [Fact]
    public async Task A_first_scan_opens_findings_for_failures_only()
    {
        var (analyst, org) = await NewOrganizationAsync();
        var import = await analyst.ImportCreatedAsync(org, BaselineA);

        Assert.False(import.Duplicate);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Bytes(BaselineA))), import.FileSha256);
        Assert.Equal([new ImportScan("aws", AccountA, T1)], import.Scans);
        Assert.Equal(new ImportObservationCounts(Received: 10, Recorded: 10, AlreadyKnown: 0, Collapsed: 0), import.Observations);
        Assert.Equal(new ImportFindingCounts(Opened: 6, Reopened: 0, Fixed: 0), import.Findings);

        var findings = await analyst.FindingsAsync(org);
        Assert.Equal(6, findings.Count);
        Assert.All(findings, f =>
        {
            Assert.Equal(FindingStatus.Open, f.Status);
            Assert.Null(f.Verification);
            Assert.Equal(T1, f.OpenSince);
            Assert.True(f.Reassessed);
        });

        // PASS baselines and MANUAL results are not findings.
        Assert.DoesNotContain(findings, f => f.ResourceName == "k9-assets");
        Assert.DoesNotContain(findings, f => f.ResourceName == "alice-access-key-2");
        Assert.DoesNotContain(findings, f => f.CheckId == ContactsCheck);
        // A FAIL muted in Prowler is still a failure; the mute is shown, not obeyed.
        Assert.True(findings.Single(SecurityGroupCheck, "sg-0b2").MutedInSource);
        // Two access keys sharing one ARN, and one ARN in two regions, stay separate.
        findings.Single(KeyRotationCheck, "alice-access-key-1");
        findings.Single(AmiBlockCheck, location: "eu-west-1");
    }

    [Fact]
    public async Task Only_a_newer_matching_PASS_fixes_a_finding()
    {
        var (analyst, org) = await NewOrganizationAsync();
        await analyst.ImportCreatedAsync(org, BaselineA);
        var followup = await analyst.ImportCreatedAsync(org, FollowupA);

        Assert.Equal(new ImportFindingCounts(Opened: 2, Reopened: 0, Fixed: 3), followup.Findings);
        var findings = await analyst.FindingsAsync(org);

        var logs = findings.Single(BucketCheck, "k9-logs");
        Assert.Equal(FindingStatus.Fixed, logs.Status);
        Assert.Equal("scanner_reported", logs.Verification);
        Assert.Equal(T2, logs.FixedAt);
        Assert.Equal(T2, logs.DecidedAt);

        Assert.Equal(FindingStatus.Fixed, findings.Single(KeyRotationCheck, "alice-access-key-1").Status);

        // The same ARN moved in opposite directions in two regions.
        Assert.Equal(FindingStatus.Fixed, findings.Single(AmiBlockCheck, location: "eu-west-1").Status);
        Assert.Equal(FindingStatus.Open, findings.Single(AmiBlockCheck, location: "us-east-1").Status);

        // A PASS baseline followed by a FAIL opens a finding; it was never fixed, so it is not a reopen.
        var assets = findings.Single(BucketCheck, "k9-assets");
        Assert.Equal((FindingStatus.Open, false, T2), (assets.Status, assets.Reopened, assets.OpenSince));

        // Missing from the newer scan: still open, flagged as not reassessed.
        var missing = findings.Single(SecurityGroupCheck, "sg-0a1");
        Assert.Equal((FindingStatus.Open, false, T1), (missing.Status, missing.Reassessed, missing.LastObservedAt));

        // A muted PASS is not evidence of a fix.
        var muted = findings.Single(SecurityGroupCheck, "sg-0b2");
        Assert.Equal((FindingStatus.Open, true, true, T1), (muted.Status, muted.NeedsReview, muted.MutedInSource, muted.DecidedAt));

        // Still failing: open, decided by the newer evidence.
        var root = findings.Single(RootMfaCheck);
        Assert.Equal((FindingStatus.Open, T2, T2), (root.Status, root.DecidedAt, root.LastObservedAt));

        Assert.Equal(8, findings.Count);
        Assert.Equal(5, (await analyst.FindingsAsync(org, "?status=open")).Count);
        Assert.Equal(3, (await analyst.FindingsAsync(org, "?status=fixed")).Count);
    }

    [Fact]
    public async Task A_failure_after_a_fix_reopens_the_finding_and_MANUAL_asks_for_review()
    {
        var (analyst, org) = await NewOrganizationAsync();
        await analyst.ImportCreatedAsync(org, BaselineA);
        await analyst.ImportCreatedAsync(org, FollowupA);
        var third = await analyst.ImportCreatedAsync(org, ThirdA);

        Assert.Equal(new ImportFindingCounts(Opened: 0, Reopened: 1, Fixed: 1), third.Findings);
        var findings = await analyst.FindingsAsync(org);

        var logs = findings.Single(BucketCheck, "k9-logs");
        Assert.Equal((FindingStatus.Open, true, T3, (DateTimeOffset?)null), (logs.Status, logs.Reopened, logs.OpenSince, logs.FixedAt));

        var manual = findings.Single(SecurityGroupCheck, "sg-0a1");
        Assert.Equal((FindingStatus.Open, true, true, T1), (manual.Status, manual.NeedsReview, manual.Reassessed, manual.DecidedAt));

        Assert.Equal(FindingStatus.Fixed, findings.Single(RootMfaCheck).Status);
        Assert.False(findings.Single(BucketCheck, "k9-assets").Reassessed);
    }

    [Fact]
    public async Task An_older_scan_imported_later_does_not_override_newer_state()
    {
        var (analyst, org) = await NewOrganizationAsync();
        await analyst.ImportCreatedAsync(org, FollowupA);
        var older = await analyst.ImportCreatedAsync(org, BaselineA);

        Assert.Equal(0, older.Findings.Fixed);
        var findings = await analyst.FindingsAsync(org);
        var logs = findings.Single(BucketCheck, "k9-logs");
        Assert.Equal((FindingStatus.Fixed, T2, T1), (logs.Status, logs.FixedAt, logs.OpenSince));
        Assert.Equal(FindingStatus.Open, findings.Single(SecurityGroupCheck, "sg-0a1").Status);
    }

    [Fact]
    public async Task Import_order_never_changes_the_result()
    {
        string[] scans = [BaselineA, FollowupA, ThirdA];
        int[][] orders = [[0, 1, 2], [2, 1, 0], [1, 0, 2], [2, 0, 1]];
        List<FindingSnapshot>? expected = null;

        foreach (var order in orders.Select(o => o.Select(i => scans[i]).ToArray()))
        {
            var (analyst, org) = await NewOrganizationAsync();
            foreach (var scan in order)
            {
                await analyst.ImportCreatedAsync(org, scan);
            }
            var snapshot = await analyst.SnapshotAsync(org);
            expected ??= snapshot;
            Assert.Equal(expected, snapshot);
        }
    }

    // ---- Duplicates and conflicts -------------------------------------------------------

    [Fact]
    public async Task Uploading_the_same_file_again_changes_nothing()
    {
        var (analyst, org) = await NewOrganizationAsync();
        var first = await analyst.ImportCreatedAsync(org, BaselineA);
        var before = await api.RowCountsAsync(org);

        var again = await analyst.ImportAsync(org, BaselineA);
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        var duplicate = (await again.Content.ReadFromJsonAsync<ImportResponse>(Json.Options))!;
        Assert.True(duplicate.Duplicate);
        Assert.Equal(first.Id, duplicate.Id);
        Assert.Equal(before, await api.RowCountsAsync(org));
    }

    [Fact]
    public async Task A_re_export_of_a_known_scan_records_no_new_observations()
    {
        var (analyst, org) = await NewOrganizationAsync();
        await analyst.ImportCreatedAsync(org, BaselineA);
        await analyst.ImportCreatedAsync(org, FollowupA);
        var snapshot = await analyst.SnapshotAsync(org);
        var observations = (await api.RowCountsAsync(org)).Observations;

        var reexport = await analyst.ImportCreatedAsync(org, ReexportA);

        Assert.False(reexport.Duplicate);
        Assert.Equal(new ImportObservationCounts(Received: 9, Recorded: 0, AlreadyKnown: 9, Collapsed: 0), reexport.Observations);
        Assert.Equal(new ImportFindingCounts(0, 0, 0), reexport.Findings);
        Assert.Equal(observations, (await api.RowCountsAsync(org)).Observations);
        Assert.Equal(snapshot, await analyst.SnapshotAsync(org));
    }

    [Fact]
    public async Task A_conflicting_observation_rejects_the_whole_file()
    {
        var (analyst, org) = await NewOrganizationAsync();
        await analyst.ImportCreatedAsync(org, FollowupA);
        var before = await api.RowCountsAsync(org);
        var snapshot = await analyst.SnapshotAsync(org);

        // The conflict plus a valid, new scan of account B: none of it may be written.
        var response = await analyst.ImportAsync(org, Combine(ConflictA, BaselineB));
        var rejection = await AssessmentScenario.ProblemsAsync(response, HttpStatusCode.Conflict);

        var problem = Assert.Single(rejection.Problems);
        Assert.Equal(ImportProblemCodes.ConflictingObservation, problem.Code);
        Assert.Equal((BucketCheck, "arn:aws:s3:::k9-logs", "eu-west-1"), (problem.CheckId, problem.ResourceUid, problem.Location));
        Assert.Equal(before, await api.RowCountsAsync(org));
        Assert.Equal(snapshot, await analyst.SnapshotAsync(org));
        Assert.DoesNotContain(await analyst.FindingsAsync(org), f => f.AccountUid == AccountB);
    }

    [Fact]
    public async Task A_PASS_with_the_same_scan_time_as_a_FAIL_does_not_fix_it()
    {
        var (analyst, org) = await NewOrganizationAsync();
        await analyst.ImportCreatedAsync(org, ConflictA); // k9-logs FAIL at T2

        var response = await analyst.ImportAsync(org, FollowupA); // k9-logs PASS at T2
        await AssessmentScenario.ProblemsAsync(response, HttpStatusCode.Conflict);

        var logs = Assert.Single(await analyst.FindingsAsync(org));
        Assert.Equal(FindingStatus.Open, logs.Status);
    }

    [Fact]
    public async Task Identical_duplicates_within_a_file_are_recorded_once()
    {
        var (analyst, org) = await NewOrganizationAsync();
        var import = await analyst.ImportCreatedAsync(org, InFileDuplicate);

        Assert.Equal(new ImportObservationCounts(Received: 2, Recorded: 1, AlreadyKnown: 0, Collapsed: 1), import.Observations);
        Assert.Equal(1, (await api.RowCountsAsync(org)).Observations);
    }

    [Fact]
    public async Task Resources_sharing_a_Prowler_finding_uid_are_tracked_separately()
    {
        var (analyst, org) = await NewOrganizationAsync();
        var import = await analyst.ImportCreatedAsync(org, UidCollision);

        Assert.Equal(2, import.Observations.Recorded);
        var finding = Assert.Single(await analyst.FindingsAsync(org));
        Assert.EndsWith("sg-0c3", finding.ResourceUid);
    }

    [Fact]
    public async Task A_file_with_several_accounts_is_one_import_with_one_scan_per_account()
    {
        var (analyst, org) = await NewOrganizationAsync();
        var import = await analyst.ImportCreatedAsync(org, MultiAccount);

        Assert.Equal([new ImportScan("aws", AccountA, T3), new ImportScan("aws", AccountB, T1)],
            import.Scans.OrderBy(s => s.AccountUid, StringComparer.Ordinal));
        var findings = await analyst.FindingsAsync(org);
        Assert.Equal(2, findings.Count(f => f.AccountUid == AccountB));
        // The same security group ID in two accounts is two resources.
        Assert.DoesNotContain(findings, f => f.AccountUid == AccountA && f.ResourceName == "sg-0a1");
    }

    // ---- Rejected files ----------------------------------------------------------------

    public static TheoryData<string, byte[], string> RejectedFiles()
    {
        var baseline = Bytes(BaselineA);
        return new()
        {
            { "truncated", baseline[..(baseline.Length / 2)], ImportProblemCodes.MalformedJson },
            { "older Prowler", MutateFirst(BaselineA, f => f["metadata"]!["product"]!["version"] = "5.43.0"), ImportProblemCodes.UnsupportedProwlerVersion },
            { "Azure", Bytes(AzureUnsupported), ImportProblemCodes.UnsupportedProvider },
            { "mixed scan times", Mutate(BaselineA, f => f[3]!["time"] = T1.ToUnixTimeSeconds() + 1), ImportProblemCodes.MixedScanTimes },
            { "contradiction in the file", Bytes(InFileContradiction), ImportProblemCodes.InFileConflict },
            { "empty scan", "[]"u8.ToArray(), ImportProblemCodes.NoObservations },
            { "too many observations", TooManyObservations(), ImportProblemCodes.TooManyObservations },
        };
    }

    [Theory]
    [MemberData(nameof(RejectedFiles))]
    public async Task Rejected_files_leave_nothing_behind_and_are_audited(string because, byte[] file, string code)
    {
        var (analyst, org) = await NewOrganizationAsync();
        var response = await analyst.ImportAsync(org, file);
        var rejection = await AssessmentScenario.ProblemsAsync(response, HttpStatusCode.BadRequest);

        Assert.Contains(rejection.Problems, p => p.Code == code);
        Assert.True(rejection.Problems.Count <= ProwlerOcsfContract.MaxProblemsReported, because);
        Assert.Equal(new AssessmentRowCounts(0, 0, 0, 0), await api.RowCountsAsync(org));

        var failure = Assert.Single((await analyst.AuditAsync(org, $"?action={AssessmentScenario.ImportAction}")).Items);
        Assert.Equal("failure", failure.Outcome);
        Assert.Equal(code, failure.Details!.Value.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Rejections_never_echo_finding_content()
    {
        var (analyst, org) = await NewOrganizationAsync();
        const string Secret = "AKIAK9SECRETVALUE0001";
        var file = MutateFirst(BaselineA, f =>
        {
            f["metadata"]!["product"]!["version"] = "0.0.1";
            f["status_detail"] = Secret;
            f["resources"]![0]!["name"] = Secret;
        });

        var response = await analyst.ImportAsync(org, file);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain(Secret, await response.Content.ReadAsStringAsync());
        var audit = (await analyst.AuditAsync(org, $"?action={AssessmentScenario.ImportAction}")).Items;
        Assert.DoesNotContain(audit, e => e.Details?.GetRawText().Contains(Secret, StringComparison.Ordinal) == true);
    }

    [Fact]
    public async Task Oversized_uploads_are_refused()
    {
        var (analyst, org) = await NewOrganizationAsync();
        // Valid JSON, padded past the limit with whitespace.
        var padded = Encoding.UTF8.GetBytes("[" + new string(' ', (int)TestLimits.MaxFileBytes) + "]");

        var response = await analyst.ImportAsync(org, padded);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal(new AssessmentRowCounts(0, 0, 0, 0), await api.RowCountsAsync(org));
    }

    [Fact]
    public async Task Only_JSON_is_accepted()
    {
        var (analyst, org) = await NewOrganizationAsync();
        var response = await analyst.ImportAsync(org, Bytes(BaselineA), contentType: "text/plain");
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    // ---- Provenance --------------------------------------------------------------------

    [Fact]
    public async Task Every_finding_shows_the_observations_and_imports_behind_it()
    {
        var (analyst, org) = await NewOrganizationAsync();
        var baseline = await analyst.ImportCreatedAsync(org, BaselineA);
        var followup = await analyst.ImportCreatedAsync(org, FollowupA);

        var logs = (await analyst.FindingsAsync(org)).Single(BucketCheck, "k9-logs");
        var detail = await analyst.FindingAsync(org, logs.Id);

        Assert.Equal(logs.Id, detail.Finding.Id);
        Assert.Equal([T1, T2], detail.Observations.Select(o => o.ScanTime));
        Assert.Equal([baseline.Id, followup.Id], detail.Observations.Select(o => o.ImportId));
        Assert.Equal([CheckResult.Fail, CheckResult.Pass], detail.Observations.Select(o => o.Result));
        Assert.Equal(detail.Observations[1].Id, detail.Finding.DecisiveObservationId);
        Assert.All(detail.Observations, o =>
        {
            Assert.Equal($"prowler-aws-{BucketCheck}-{AccountA}-eu-west-1-k9-logs", o.ProwlerFindingUid);
            Assert.Equal(ProwlerVersion, o.ProwlerVersion);
            Assert.NotNull(o.ProwlerScanId);
        });
        Assert.Contains("is configured", detail.Observations[1].StatusDetail);

        var history = await analyst.ImportHistoryAsync(org);
        Assert.Equal([followup.Id, baseline.Id], history.Select(i => i.Id));
    }

    [Fact]
    public async Task Stored_observations_can_be_re_fingerprinted_from_their_canonical_content()
    {
        var (analyst, org) = await NewOrganizationAsync();
        await analyst.ImportCreatedAsync(org, BaselineA);

        await using var connection = new Npgsql.NpgsqlConnection(api.SuperuserConnectionString);
        await connection.OpenAsync();
        await using var command = new Npgsql.NpgsqlCommand(
            "SELECT fingerprint_version, canonical_content, fingerprint FROM finding_observations WHERE organization_id = @o", connection);
        command.Parameters.AddWithValue("o", org);
        await using var reader = await command.ExecuteReaderAsync();
        var rows = 0;
        while (await reader.ReadAsync())
        {
            rows++;
            Assert.Equal(ObservationFingerprint.CurrentVersion, reader.GetInt32(0));
            Assert.Equal(ObservationFingerprint.Compute(reader.GetString(1), reader.GetInt32(0)), (byte[])reader[2]);
        }
        Assert.Equal(10, rows);
    }

    // ---- Audit -------------------------------------------------------------------------

    [Fact]
    public async Task Successful_imports_are_audited_with_their_outcome()
    {
        var (analyst, org) = await NewOrganizationAsync();
        var response = await analyst.ImportAsync(org, BaselineA);
        var import = (await response.Content.ReadFromJsonAsync<ImportResponse>(Json.Options))!;

        var recorded = Assert.Single((await analyst.AuditAsync(org, $"?action={AssessmentScenario.ImportAction}")).Items);
        Assert.Equal("success", recorded.Outcome);
        Assert.Equal(analyst.Id, recorded.ActorUserId);
        Assert.Equal(Scenario.CorrelationIdOf(response), recorded.CorrelationId);
        Assert.Equal(("assessment_import", import.Id.ToString()), (recorded.ResourceType, recorded.ResourceId));
        var details = recorded.Details!.Value;
        Assert.Equal(import.FileSha256, details.GetProperty("file_sha256").GetString());
        Assert.Equal("10", details.GetProperty("observations_recorded").GetString());
        Assert.Equal("6", details.GetProperty("findings_opened").GetString());
    }

    [Fact]
    public async Task Imports_fail_closed_when_the_audit_log_is_unavailable()
    {
        var (analyst, org) = await NewOrganizationAsync();
        const string Function = "k9_record_audit_event(text, text, uuid, text, text, text, inet, jsonb)";
        await Scenario.ExecuteAsync(api.SuperuserConnectionString, $"REVOKE EXECUTE ON FUNCTION {Function} FROM k9_app");
        try
        {
            var response = await analyst.ImportAsync(org, BaselineA);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal(new AssessmentRowCounts(0, 0, 0, 0), await api.RowCountsAsync(org));
        }
        finally
        {
            await Scenario.ExecuteAsync(api.SuperuserConnectionString, $"GRANT EXECUTE ON FUNCTION {Function} TO k9_app");
        }
        await analyst.ImportCreatedAsync(org, BaselineA);
    }

    private static byte[] TooManyObservations() => Mutate(BaselineA, findings =>
    {
        var template = findings[0]!;
        for (var i = findings.Count; i <= TestLimits.MaxObservations; i++)
        {
            var copy = template.DeepClone();
            copy["resources"]![0]!["uid"] = $"arn:aws:s3:::k9-bucket-{i}";
            copy["resources"]![0]!["name"] = $"k9-bucket-{i}";
            findings.Add(copy);
        }
    });
}
