using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using K9.Api.Assessments;
using K9.Api.Tests.Infrastructure;
using static K9.Api.Tests.Infrastructure.ProwlerFixtures;

namespace K9.Api.Tests.Assessments;

/// <summary>
/// Fingerprint version 1: SHA-256 over a versioned, explicit allowlist. It must ignore what
/// changes between exports of one scan and catch every change in what the scan said.
/// </summary>
public sealed class ObservationFingerprintTests
{
    [Fact]
    public void Canonical_content_holds_exactly_the_allowlisted_fields_in_sorted_order()
    {
        var content = ObservationFingerprint.CanonicalContent(Observations.Sample());

        using var document = JsonDocument.Parse(content);
        var names = document.RootElement.EnumerateObject().Select(p => p.Name).ToList();
        Assert.Equal(ObservationFingerprint.Version1Fields, names);
        Assert.Equal(names.Order(StringComparer.Ordinal), names);
        Assert.DoesNotContain(content, c => char.IsWhiteSpace(c) && c != ' ');
        Assert.Equal(JsonSerializer.Serialize(document.RootElement), content);
    }

    [Fact]
    public void Version_1_is_pinned()
    {
        // Stored fingerprints must stay comparable forever. If this test has to change, the
        // change needs a new fingerprint version, not an edit to version 1.
        var sample = Observations.Sample() with { StatusDetail = "Bucket k9-logs is public." };
        const string Expected = """{"muted":false,"resource_type":"AwsS3Bucket","result":"FAIL","severity_id":4,"status_detail":"Bucket k9-logs is public."}""";

        Assert.Equal(Expected, ObservationFingerprint.CanonicalContent(sample, version: 1));
        Assert.Equal(
            SHA256.HashData(Encoding.UTF8.GetBytes("k9-observation-fingerprint:v1\n" + Expected)),
            ObservationFingerprint.Compute(Expected, version: 1));
    }

    public static TheoryData<string, Func<ParsedObservation, ParsedObservation>> EvidenceChanges => new()
    {
        { "result", o => o with { Result = CheckResult.Pass } },
        { "result (manual)", o => o with { Result = CheckResult.Manual } },
        { "muted", o => o with { Muted = true } },
        { "severity", o => o with { SeverityId = 5 } },
        { "status detail", o => o with { StatusDetail = o.StatusDetail + " (changed)" } },
        { "resource type", o => o with { ResourceType = "AwsS3AccessPoint" } },
    };

    [Theory]
    [MemberData(nameof(EvidenceChanges))]
    public void Every_allowlisted_field_changes_the_fingerprint(string field, Func<ParsedObservation, ParsedObservation> change)
    {
        var sample = Observations.Sample();
        Assert.False(Fingerprint(sample).AsSpan().SequenceEqual(Fingerprint(change(sample))), $"changing {field} kept the fingerprint");
    }

    [Fact]
    public void Fields_outside_the_allowlist_do_not_change_the_fingerprint()
    {
        var sample = Observations.Sample();
        var other = sample with
        {
            Index = 9, Title = "another title", Severity = "Low", Remediation = null, ProwlerFindingUid = "prowler-other",
            ProwlerScanId = "01a08075-d100-73ce-a2d4-a6d297b75092", ProwlerVersion = "5.44.1", OcsfVersion = "1.5.1",
        };
        Assert.Equal(Fingerprint(sample), Fingerprint(other));
    }

    [Fact]
    public void Unknown_versions_are_refused()
    {
        var content = ObservationFingerprint.CanonicalContent(Observations.Sample());
        Assert.Throws<ArgumentOutOfRangeException>(() => ObservationFingerprint.Compute(content, version: 2));
        Assert.Throws<ArgumentOutOfRangeException>(() => ObservationFingerprint.Compute(content, version: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => ObservationFingerprint.CanonicalContent(Observations.Sample(), version: 2));
    }

    [Fact]
    public void Non_ASCII_evidence_round_trips()
    {
        var sample = Observations.Sample() with { StatusDetail = "Bucket «k9-logs» — naïve \"quoted\" \\ <tag> & 日本" };
        using var document = JsonDocument.Parse(ObservationFingerprint.CanonicalContent(sample));
        Assert.Equal(sample.StatusDetail, document.RootElement.GetProperty("status_detail").GetString());
    }

    // ---- Against real Prowler output ---------------------------------------------------

    [Fact]
    public async Task A_re_export_with_a_new_scan_ID_and_another_order_has_the_same_fingerprints()
    {
        Assert.Equal(Fingerprints(await ReadValidAsync(FollowupA)), Fingerprints(await ReadValidAsync(ReexportA)));
    }

    [Fact]
    public async Task Resource_dumps_and_property_order_do_not_change_fingerprints()
    {
        var original = Fingerprints(await ReadValidAsync(BaselineA));
        var file = Mutate(BaselineA, findings =>
        {
            foreach (var finding in findings.Select(n => n!.AsObject()))
            {
                finding["resources"]![0]!["data"] = new JsonObject { ["metadata"] = new JsonObject { ["LastUsed"] = "2026-10-12T00:00:00Z" } };
                finding["unmapped"]!["scan_id"] = Guid.NewGuid().ToString();
                finding["unmapped"]!["compliance"] = new JsonObject { ["CIS-3.0"] = new JsonArray("1.5") };
                var properties = finding.ToList();
                finding.Clear();
                foreach (var (name, value) in properties.AsEnumerable().Reverse())
                {
                    finding[name] = value;
                }
            }
        });
        var result = await ReadAsync(file);
        Assert.True(result.Succeeded);
        Assert.Equal(original, Fingerprints(result.Observations));
    }

    [Fact]
    public async Task A_changed_result_for_the_same_scan_changes_the_fingerprint()
    {
        var followup = Assert.Single(await ReadValidAsync(FollowupA), o => o.ResourceName == "k9-logs");
        var conflict = Assert.Single(await ReadValidAsync(ConflictA));
        Assert.Equal((followup.ScanTime, followup.ResourceUid), (conflict.ScanTime, conflict.ResourceUid));
        Assert.NotEqual(Fingerprint(followup), Fingerprint(conflict));
    }

    private static byte[] Fingerprint(ParsedObservation observation) =>
        ObservationFingerprint.Compute(ObservationFingerprint.CanonicalContent(observation));

    private static SortedDictionary<string, string> Fingerprints(IEnumerable<ParsedObservation> observations) =>
        new(observations.ToDictionary(
            o => CanonicalIdentity.For(Guid.Empty, o).CanonicalKey,
            o => Convert.ToHexString(Fingerprint(o))), StringComparer.Ordinal);
}
