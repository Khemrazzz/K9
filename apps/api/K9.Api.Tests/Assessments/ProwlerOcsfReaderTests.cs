using System.Text;
using System.Text.Json.Nodes;
using K9.Api.Assessments;
using K9.Api.Tests.Infrastructure;
using static K9.Api.Tests.Infrastructure.ProwlerFixtures;

namespace K9.Api.Tests.Assessments;

/// <summary>The supported OCSF input (docs/prowler-import-contract.md), against Prowler 5.44.0 output.</summary>
public sealed class ProwlerOcsfReaderTests
{
    public static TheoryData<string> AcceptedFixtures()
    {
        var data = new TheoryData<string>();
        foreach (var fixture in All().Where(f => f is not AzureUnsupported and not InFileContradiction))
        {
            data.Add(fixture);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(AcceptedFixtures))]
    public async Task Prowler_output_is_accepted(string fixture)
    {
        var observations = await ReadValidAsync(fixture);
        Assert.NotEmpty(observations);
        Assert.All(observations, o =>
        {
            Assert.Equal("aws", o.Provider);
            Assert.Equal(ProwlerVersion, o.ProwlerVersion);
            Assert.Equal("1.5.0", o.OcsfVersion);
            Assert.Equal(TimeSpan.Zero, o.ScanTime.Offset);
        });
    }

    [Fact]
    public async Task Contract_fields_are_read_from_their_documented_locations()
    {
        var observations = await ReadValidAsync(BaselineA);
        var legacy = Assert.Single(observations, o => o.ResourceName == "sg-0b2");

        Assert.Equal(SecurityGroupCheck, legacy.CheckId);
        Assert.Equal(AccountA, legacy.AccountUid);
        Assert.Equal("eu-west-1", legacy.Location);
        Assert.Equal($"arn:aws:ec2:eu-west-1:{AccountA}:security-group/sg-0b2", legacy.ResourceUid);
        Assert.Equal(T1, legacy.ScanTime);
        Assert.Equal(CheckResult.Fail, legacy.Result);
        Assert.True(legacy.Muted);
        Assert.Equal(5, legacy.SeverityId);
        Assert.Equal("Critical", legacy.Severity);
        Assert.Equal("AwsEc2SecurityGroup", legacy.ResourceType);
        Assert.Equal("Security group legacy (sg-0b2) has all ports open to the Internet.", legacy.StatusDetail);
        Assert.Equal("Security group does not have all ports open to the Internet", legacy.Title);
        Assert.Equal($"prowler-aws-{SecurityGroupCheck}-{AccountA}-eu-west-1-sg-0b2", legacy.ProwlerFindingUid);
        Assert.Matches("^[0-9a-f-]{36}$", legacy.ProwlerScanId);
        Assert.Equal(Enumerable.Range(0, observations.Count), observations.Select(o => o.Index).Order());
    }

    [Fact]
    public async Task The_result_comes_from_status_code_and_muting_from_status_id()
    {
        var observations = await ReadValidAsync(BaselineA);

        var unmutedFail = Assert.Single(observations, o => o.ResourceName == "sg-0a1");
        Assert.Equal((CheckResult.Fail, false), (unmutedFail.Result, unmutedFail.Muted));
        var mutedFail = Assert.Single(observations, o => o.ResourceName == "sg-0b2");
        Assert.Equal((CheckResult.Fail, true), (mutedFail.Result, mutedFail.Muted));
        var manual = Assert.Single(observations, o => o.CheckId == ContactsCheck);
        Assert.Equal((CheckResult.Manual, false), (manual.Result, manual.Muted));
        var pass = Assert.Single(observations, o => o.ResourceName == "k9-assets");
        Assert.Equal((CheckResult.Pass, false), (pass.Result, pass.Muted));
    }

    [Fact]
    public async Task Prowler_MUTED_status_code_is_read_as_a_non_conclusive_result()
    {
        var result = await ReadAsync(MutateFirst(BaselineA, f => f["status_code"] = "MUTED"));
        Assert.True(result.Succeeded);
        Assert.Equal(CheckResult.Muted, result.Observations[0].Result);
    }

    [Fact]
    public async Task Access_keys_sharing_one_ARN_and_one_ARN_in_two_regions_are_kept_as_separate_observations()
    {
        var observations = await ReadValidAsync(BaselineA);

        var keys = observations.Where(o => o.CheckId == KeyRotationCheck).ToList();
        Assert.Equal(2, keys.Count);
        Assert.Single(keys.Select(k => k.ResourceUid).Distinct());
        Assert.Equal(["alice-access-key-1", "alice-access-key-2"], keys.Select(k => k.ResourceName).Order());

        var ami = observations.Where(o => o.CheckId == AmiBlockCheck).ToList();
        Assert.Single(ami.Select(a => a.ResourceUid).Distinct());
        Assert.Equal(["eu-west-1", "us-east-1"], ami.Select(a => a.Location).Order());
    }

    [Fact]
    public async Task Prowler_finding_uid_collisions_do_not_merge_observations()
    {
        var observations = await ReadValidAsync(UidCollision);
        Assert.Equal(2, observations.Count);
        Assert.Single(observations.Select(o => o.ProwlerFindingUid).Distinct());
        Assert.Equal(2, observations.Select(o => o.ResourceUid).Distinct().Count());
    }

    [Fact]
    public async Task Scan_time_comes_from_time_and_time_dt_is_ignored()
    {
        // Real CLI exports write time_dt in the scanning machine's local time without an offset.
        foreach (var timeDt in new JsonNode?[] { "2026-09-01T13:00:00.123456", "not a date", null })
        {
            var file = Mutate(BaselineA, findings =>
            {
                foreach (var f in findings.Select(n => n!.AsObject()))
                {
                    f["time_dt"] = timeDt?.DeepClone();
                    f["finding_info"]!["created_time_dt"] = timeDt?.DeepClone();
                }
            });
            var result = await ReadAsync(file);
            Assert.True(result.Succeeded, $"time_dt {timeDt?.ToJsonString() ?? "null"} rejected the file");
            Assert.All(result.Observations, o => Assert.Equal(T1, o.ScanTime));
        }
    }

    [Fact]
    public async Task The_scan_id_is_optional()
    {
        var result = await ReadAsync(MutateFirst(BaselineA, f => f["unmapped"]!.AsObject().Remove("scan_id")));
        Assert.True(result.Succeeded);
        Assert.Null(result.Observations[0].ProwlerScanId);
    }

    [Fact]
    public async Task Long_status_details_are_truncated_not_rejected()
    {
        var result = await ReadAsync(MutateFirst(BaselineA, f => f["status_detail"] = new string('x', 10_000)));
        Assert.True(result.Succeeded);
        Assert.Equal(ProwlerOcsfContract.MaxStatusDetailLength, result.Observations[0].StatusDetail.Length);
    }

    // ---- Per-finding rejections --------------------------------------------------------

    public static TheoryData<string, Action<JsonObject>, string> InvalidFindings => new()
    {
        { "older Prowler", f => f["metadata"]!["product"]!["version"] = "5.43.0", ImportProblemCodes.UnsupportedProwlerVersion },
        { "newer Prowler", f => f["metadata"]!["product"]!["version"] = "6.0.0", ImportProblemCodes.UnsupportedProwlerVersion },
        { "other product", f => f["metadata"]!["product"]!["uid"] = "not-prowler", ImportProblemCodes.UnsupportedProwlerVersion },
        { "other OCSF version", f => f["metadata"]!["version"] = "1.4.0", ImportProblemCodes.UnsupportedOcsfVersion },
        { "not a detection finding", f => f["class_uid"] = 2003, ImportProblemCodes.UnsupportedClass },
        { "check IDs disagree", f => f["metadata"]!["event_code"] = "iam_root_mfa_enabled", ImportProblemCodes.CheckIdMismatch },
        { "no analytic", f => f["finding_info"]!.AsObject().Remove("analytic"), ImportProblemCodes.MissingField },
        { "malformed check ID", f => SetCheckId(f, "S3 Bucket; DROP TABLE"), ImportProblemCodes.InvalidField },
        { "overlong check ID", f => SetCheckId(f, new string('a', 129)), ImportProblemCodes.InvalidField },
        { "no resources", f => f["resources"] = new JsonArray(), ImportProblemCodes.ResourceCount },
        { "two resources", f => f["resources"]!.AsArray().Add(f["resources"]![0]!.DeepClone()), ImportProblemCodes.ResourceCount },
        { "no resource uid", f => f["resources"]![0]!.AsObject().Remove("uid"), ImportProblemCodes.MissingField },
        { "overlong resource uid", f => f["resources"]![0]!["uid"] = "arn:aws:s3:::" + new string('a', 2048), ImportProblemCodes.InvalidField },
        { "no resource name", f => f["resources"]![0]!.AsObject().Remove("name"), ImportProblemCodes.MissingField },
        { "no account", f => f["cloud"]!["account"]!.AsObject().Remove("uid"), ImportProblemCodes.MissingField },
        { "malformed AWS account", f => f["cloud"]!["account"]!["uid"] = "12345", ImportProblemCodes.InvalidField },
        { "malformed region", f => SetRegion(f, "EU West 1"), ImportProblemCodes.InvalidField },
        { "regions disagree", f => f["cloud"]!["region"] = "us-east-1", ImportProblemCodes.LocationMismatch },
        { "providers disagree", f => f["unmapped"]!["provider"] = "azure", ImportProblemCodes.ProviderMismatch },
        { "unknown result", f => f["status_code"] = "ERROR", ImportProblemCodes.UnknownResult },
        { "no result", f => f.Remove("status_code"), ImportProblemCodes.MissingField },
        { "non-numeric status_id", f => f["status_id"] = "Suppressed", ImportProblemCodes.InvalidField },
        { "no time", f => f.Remove("time"), ImportProblemCodes.MissingField },
        { "time as text", f => f["time"] = "2026-09-01T10:00:00Z", ImportProblemCodes.InvalidField },
        { "fractional time", f => f["time"] = 1788256800.5, ImportProblemCodes.InvalidField },
        { "negative time", f => f["time"] = -1, ImportProblemCodes.InvalidField },
        { "finding is not an object", f => f.Clear(), ImportProblemCodes.MissingField },
    };

    [Theory]
    [MemberData(nameof(InvalidFindings))]
    public async Task Invalid_findings_reject_the_file(string because, Action<JsonObject> change, string code)
    {
        var result = await ReadAsync(MutateFirst(BaselineA, change));

        Assert.False(result.Succeeded, $"accepted a file with {because}");
        Assert.Empty(result.Observations);
        var problem = Assert.Single(result.Problems);
        Assert.Equal(code, problem.Code);
        Assert.Equal(0, problem.Index);
    }

    [Fact]
    public async Task An_array_element_that_is_not_an_object_is_rejected()
    {
        var result = await ReadAsync(Mutate(BaselineA, findings => findings.Insert(2, 42)));
        var problem = Assert.Single(result.Problems);
        Assert.Equal((ImportProblemCodes.InvalidField, 2), (problem.Code, problem.Index));
    }

    [Fact]
    public async Task One_account_with_two_scan_times_in_one_file_is_rejected()
    {
        var result = await ReadAsync(Mutate(BaselineA, findings => findings[3]!["time"] = T1.ToUnixTimeSeconds() + 1));
        Assert.Contains(result.Problems, p => p.Code == ImportProblemCodes.MixedScanTimes);
        Assert.Empty(result.Observations);
    }

    [Fact]
    public async Task Unsupported_providers_are_rejected()
    {
        var result = await ReadAsync(Bytes(AzureUnsupported));
        Assert.Equal(ImportProblemCodes.UnsupportedProvider, Assert.Single(result.Problems).Code);
    }

    // ---- Whole-file rejections ---------------------------------------------------------

    public static TheoryData<string, byte[], string> InvalidFiles()
    {
        var baseline = Bytes(BaselineA);
        var nested = new StringBuilder("[{\"x\":");
        for (var i = 0; i < 100; i++)
        {
            nested.Append("{\"x\":");
        }
        return new TheoryData<string, byte[], string>
        {
            { "empty array", "[]"u8.ToArray(), ImportProblemCodes.NoObservations },
            { "empty file", [], ImportProblemCodes.MalformedJson },
            { "object root", "{\"findings\":[]}"u8.ToArray(), ImportProblemCodes.NotAnArray },
            { "null root", "null"u8.ToArray(), ImportProblemCodes.NotAnArray },
            { "truncated", baseline[..(baseline.Length / 2)], ImportProblemCodes.MalformedJson },
            { "trailing data", [.. baseline, .. "{}"u8.ToArray()], ImportProblemCodes.MalformedJson },
            { "two documents", [.. baseline, .. baseline], ImportProblemCodes.MalformedJson },
            { "deeply nested", Encoding.UTF8.GetBytes(nested.ToString()), ImportProblemCodes.MalformedJson },
            { "invalid UTF-8", [(byte)'[', (byte)'"', 0xC3, 0x28, (byte)'"', (byte)']'], ImportProblemCodes.MalformedJson },
            { "not JSON", "<html>scan failed</html>"u8.ToArray(), ImportProblemCodes.MalformedJson },
        };
    }

    [Theory]
    [MemberData(nameof(InvalidFiles))]
    public async Task Invalid_files_are_rejected(string because, byte[] file, string code)
    {
        var result = await ReadAsync(file);
        Assert.False(result.Succeeded, $"accepted {because}");
        Assert.Empty(result.Observations);
        Assert.Equal(code, Assert.Single(result.Problems).Code);
    }

    [Fact]
    public async Task Files_over_the_byte_limit_are_rejected_without_reading_them_to_the_end()
    {
        var file = Bytes(BaselineA);
        var stream = new CountingStream(new MemoryStream([.. file, .. new byte[1024 * 1024]]));
        var result = await ProwlerOcsfReader.ReadAsync(stream, new AssessmentImportOptions { MaxFileBytes = 1000 });

        Assert.Equal(ImportProblemCodes.FileTooLarge, Assert.Single(result.Problems).Code);
        Assert.True(stream.BytesRead < 512 * 1024, $"read {stream.BytesRead} bytes of an oversized file");
    }

    [Fact]
    public async Task Files_over_the_observation_limit_are_rejected()
    {
        var result = await ReadAsync(Bytes(BaselineA), new AssessmentImportOptions { MaxObservations = 9 });
        Assert.Equal(ImportProblemCodes.TooManyObservations, Assert.Single(result.Problems).Code);
        Assert.Empty(result.Observations);
    }

    [Fact]
    public async Task Reported_problems_are_bounded()
    {
        var file = Mutate(BaselineA, findings =>
        {
            var template = findings[0]!.DeepClone();
            template["metadata"]!["product"]!["version"] = "1.0.0";
            findings.Clear();
            for (var i = 0; i < 50; i++)
            {
                findings.Add(template.DeepClone());
            }
        });
        var result = await ReadAsync(file);

        Assert.Equal(ProwlerOcsfContract.MaxProblemsReported, result.Problems.Count);
        Assert.True(result.ProblemsTruncated);
    }

    // ---- Duplicates within one file -----------------------------------------------------

    [Fact]
    public async Task Identical_duplicates_within_a_file_collapse_into_one_observation()
    {
        var result = await ReadAsync(Bytes(InFileDuplicate));
        Assert.True(result.Succeeded);
        Assert.Single(result.Observations);
        Assert.Equal(1, result.CollapsedDuplicates);
    }

    [Fact]
    public async Task Contradicting_duplicates_within_a_file_are_rejected()
    {
        var result = await ReadAsync(Bytes(InFileContradiction));
        var problem = Assert.Single(result.Problems);
        Assert.Equal(ImportProblemCodes.InFileConflict, problem.Code);
        Assert.Equal(1, problem.Index);
        Assert.Empty(result.Observations);
    }

    private static void SetCheckId(JsonObject finding, string checkId)
    {
        finding["metadata"]!["event_code"] = checkId;
        finding["finding_info"]!["analytic"]!["uid"] = checkId;
    }

    private static void SetRegion(JsonObject finding, string region)
    {
        finding["resources"]![0]!["region"] = region;
        finding["cloud"]!["region"] = region;
    }

    private sealed class CountingStream(Stream inner) : Stream
    {
        public long BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => Count(inner.Read(buffer, offset, count));
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            Count(await inner.ReadAsync(buffer, cancellationToken));
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private int Count(int read)
        {
            BytesRead += read;
            return read;
        }
    }
}
