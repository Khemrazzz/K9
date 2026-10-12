namespace K9.Api.Assessments;

/// <summary>A Prowler <c>status_code</c>. Only FAIL and an unmuted PASS are conclusive.</summary>
public enum CheckResult
{
    Pass,
    Fail,
    Manual,
    Muted,
}

/// <summary>One validated finding from an uploaded file, before it is tied to an organization.</summary>
public sealed record ParsedObservation
{
    /// <summary>Position in the file, for error reporting.</summary>
    public required int Index { get; init; }

    // Identity (with the organization, see CanonicalIdentity).
    public required string Provider { get; init; }
    public required string AccountUid { get; init; }
    public required string CheckId { get; init; }
    public required string Location { get; init; }
    public required string ResourceUid { get; init; }
    public required string ResourceName { get; init; }

    /// <summary>From <c>time</c>, whole seconds, UTC.</summary>
    public required DateTimeOffset ScanTime { get; init; }

    // Evidence: covered by the fingerprint.
    public required CheckResult Result { get; init; }
    public required bool Muted { get; init; }
    public required int SeverityId { get; init; }
    public required string StatusDetail { get; init; }
    public required string ResourceType { get; init; }

    // Display only.
    public required string Title { get; init; }
    public required string Severity { get; init; }
    public string? Remediation { get; init; }

    // Traceability only: never identity.
    public required string ProwlerFindingUid { get; init; }
    public string? ProwlerScanId { get; init; }
    public required string ProwlerVersion { get; init; }
    public required string OcsfVersion { get; init; }
}

/// <summary>A reason a file was rejected: a code, and where. Never the finding's content.</summary>
public sealed record ImportProblem(string Code, int? Index = null, string? Field = null);

/// <summary>The outcome of reading a file: observations, or the problems that reject it.</summary>
public sealed record ReadResult(
    IReadOnlyList<ParsedObservation> Observations,
    IReadOnlyList<ImportProblem> Problems,
    bool ProblemsTruncated = false,
    int CollapsedDuplicates = 0)
{
    public bool Succeeded => Problems.Count == 0;
}
