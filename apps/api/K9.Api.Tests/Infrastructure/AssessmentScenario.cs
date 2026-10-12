using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using K9.Api.Assessments;
using Npgsql;

namespace K9.Api.Tests.Infrastructure;

// The wire contract of the assessment API (docs/prowler-import-contract.md), declared here
// rather than borrowed from the API so the tests pin the JSON clients actually see.

public sealed record ImportResponse(
    Guid Id, string FileSha256, bool Duplicate, List<ImportScan> Scans, ImportObservationCounts Observations, ImportFindingCounts Findings);

public sealed record ImportScan(string Provider, string AccountUid, DateTimeOffset ScanTime);

/// <param name="Received">Findings in the file.</param>
/// <param name="Recorded">New observations written.</param>
/// <param name="AlreadyKnown">Identical to an observation already stored.</param>
/// <param name="Collapsed">Identical duplicates within the file.</param>
public sealed record ImportObservationCounts(int Received, int Recorded, int AlreadyKnown, int Collapsed);

public sealed record ImportFindingCounts(int Opened, int Reopened, int Fixed);

public sealed record ImportProblemsResponse(int Status, List<ImportProblemItem> Problems, bool Truncated);

/// <summary>Where and why. Conflicts also name the incoming observation's own check, resource and location.</summary>
public sealed record ImportProblemItem(string Code, int? Index, string? Field, string? CheckId, string? ResourceUid, string? Location);

public sealed record ImportHistoryPage(List<ImportResponse> Items);

public sealed record FindingResponse(
    Guid Id,
    string Provider,
    string AccountUid,
    string CheckId,
    string Location,
    string ResourceUid,
    string ResourceName,
    string Title,
    string Severity,
    FindingStatus Status,
    string? Verification,
    bool Reopened,
    bool NeedsReview,
    bool MutedInSource,
    bool Reassessed,
    DateTimeOffset OpenSince,
    DateTimeOffset? FixedAt,
    DateTimeOffset DecidedAt,
    DateTimeOffset LastObservedAt,
    long DecisiveObservationId);

public sealed record FindingPage(List<FindingResponse> Items, string? NextCursor);

public sealed record ObservationResponse(
    long Id, Guid ImportId, DateTimeOffset ScanTime, CheckResult Result, bool Muted, string StatusDetail,
    string ProwlerFindingUid, string? ProwlerScanId, string ProwlerVersion);

public sealed record FindingDetailResponse(FindingResponse Finding, List<ObservationResponse> Observations);

/// <summary>A finding's state without database IDs, for comparing organizations.</summary>
public sealed record FindingSnapshot(
    string AccountUid, string CheckId, string Location, string ResourceUid, string ResourceName,
    FindingStatus Status, string? Verification, bool Reopened, bool NeedsReview, bool MutedInSource, bool Reassessed,
    DateTimeOffset OpenSince, DateTimeOffset? FixedAt, DateTimeOffset DecidedAt, DateTimeOffset LastObservedAt);

public sealed record AssessmentRowCounts(long Imports, long Observations, long Findings, long SuccessfulImportAudits);

public static class AssessmentScenario
{
    public const string ImportAction = "assessment.import";

    public static string ImportPath(Guid organizationId) => $"/api/organizations/{organizationId}/assessments/prowler/imports";

    public static Task<HttpResponseMessage> ImportAsync(this Actor actor, Guid organizationId, byte[] file, string contentType = "application/json")
    {
        var content = new ByteArrayContent(file);
        content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
        return actor.Client.PostAsync(ImportPath(organizationId), content);
    }

    public static Task<HttpResponseMessage> ImportAsync(this Actor actor, Guid organizationId, string fixture) =>
        actor.ImportAsync(organizationId, ProwlerFixtures.Bytes(fixture));

    /// <summary>Imports and requires 201 Created.</summary>
    public static async Task<ImportResponse> ImportCreatedAsync(this Actor actor, Guid organizationId, string fixture) =>
        await ExpectAsync<ImportResponse>(await actor.ImportAsync(organizationId, fixture), HttpStatusCode.Created, $"importing {fixture}");

    public static async Task<ImportProblemsResponse> ProblemsAsync(HttpResponseMessage response, HttpStatusCode expected) =>
        await ExpectAsync<ImportProblemsResponse>(response, expected, "reading the rejection");

    public static async Task<List<FindingResponse>> FindingsAsync(this Actor actor, Guid organizationId, string query = "")
    {
        var response = await actor.Client.GetAsync($"/api/organizations/{organizationId}/findings{query}");
        return (await ExpectAsync<FindingPage>(response, HttpStatusCode.OK, "listing findings")).Items;
    }

    public static async Task<FindingDetailResponse> FindingAsync(this Actor actor, Guid organizationId, Guid findingId)
    {
        var response = await actor.Client.GetAsync($"/api/organizations/{organizationId}/findings/{findingId}");
        return await ExpectAsync<FindingDetailResponse>(response, HttpStatusCode.OK, "reading a finding");
    }

    public static async Task<List<ImportResponse>> ImportHistoryAsync(this Actor actor, Guid organizationId)
    {
        var response = await actor.Client.GetAsync($"/api/organizations/{organizationId}/assessments/imports");
        return (await ExpectAsync<ImportHistoryPage>(response, HttpStatusCode.OK, "listing imports")).Items;
    }

    public static FindingResponse Single(this IEnumerable<FindingResponse> findings, string checkId, string? resourceName = null, string? location = null) =>
        Assert.Single(findings, f => f.CheckId == checkId
            && (resourceName is null || f.ResourceName == resourceName)
            && (location is null || f.Location == location));

    public static async Task<List<FindingSnapshot>> SnapshotAsync(this Actor actor, Guid organizationId) =>
        (await actor.FindingsAsync(organizationId))
            .Select(f => new FindingSnapshot(f.AccountUid, f.CheckId, f.Location, f.ResourceUid, f.ResourceName, f.Status, f.Verification,
                f.Reopened, f.NeedsReview, f.MutedInSource, f.Reassessed, f.OpenSince, f.FixedAt, f.DecidedAt, f.LastObservedAt))
            .OrderBy(s => s.AccountUid, StringComparer.Ordinal).ThenBy(s => s.CheckId, StringComparer.Ordinal)
            .ThenBy(s => s.Location, StringComparer.Ordinal).ThenBy(s => s.ResourceUid, StringComparer.Ordinal)
            .ThenBy(s => s.ResourceName, StringComparer.Ordinal)
            .ToList();

    /// <summary>Everything an import can leave behind for one organization, counted as the superuser.</summary>
    public static async Task<AssessmentRowCounts> RowCountsAsync(this K9ApiFactory api, Guid organizationId)
    {
        await using var connection = new NpgsqlConnection(api.SuperuserConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            """
            SELECT (SELECT count(*) FROM assessment_imports WHERE organization_id = @o),
                   (SELECT count(*) FROM finding_observations WHERE organization_id = @o),
                   (SELECT count(*) FROM findings WHERE organization_id = @o),
                   (SELECT count(*) FROM audit_events WHERE organization_id = @o AND action = @action AND outcome = 'success')
            """, connection);
        command.Parameters.AddWithValue("o", organizationId);
        command.Parameters.AddWithValue("action", ImportAction);
        await using var reader = await command.ExecuteReaderAsync();
        await reader.ReadAsync();
        return new AssessmentRowCounts(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3));
    }

    public static async Task<T?> ScalarAsync<T>(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        var value = await command.ExecuteScalarAsync();
        return value is null or DBNull ? default : (T)value;
    }

    private static async Task<T> ExpectAsync<T>(HttpResponseMessage response, HttpStatusCode expected, string what)
    {
        if (response.StatusCode != expected)
        {
            var body = await response.Content.ReadAsStringAsync();
            Assert.Fail($"Expected {(int)expected} {expected} when {what}, got {(int)response.StatusCode} {response.StatusCode}. "
                + (response.StatusCode == HttpStatusCode.NotFound ? "(Until PR f is implemented, the assessment endpoints do not exist.) " : "")
                + $"Body: {body[..Math.Min(body.Length, 500)]}");
        }
        return (await response.Content.ReadFromJsonAsync<T>(Json.Options))!;
    }
}
