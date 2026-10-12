namespace K9.Api.Assessments;

/// <summary>
/// The Prowler OCSF export K9 accepts. See docs/prowler-import-contract.md; the contract
/// tests in K9.Api.Tests/Assessments encode every rule.
/// </summary>
public static class ProwlerOcsfContract
{
    public static readonly IReadOnlySet<string> ProwlerVersions = new HashSet<string>(StringComparer.Ordinal) { "5.44.0" };
    public static readonly IReadOnlySet<string> OcsfVersions = new HashSet<string>(StringComparer.Ordinal) { "1.5.0" };
    public static readonly IReadOnlySet<string> Providers = new HashSet<string>(StringComparer.Ordinal) { "aws" };

    public const int DetectionFindingClassUid = 2004;
    public const int SuppressedStatusId = 3;

    public const int MaxJsonDepth = 32;
    public const int MaxCheckIdLength = 128;
    public const int MaxResourceUidLength = 2048;
    public const int MaxResourceNameLength = 1024;
    public const int MaxTitleLength = 512;
    public const int MaxRemediationLength = 4000;

    /// <summary>Longer status details are truncated to this many characters, not rejected.</summary>
    public const int MaxStatusDetailLength = 4000;

    /// <summary>A rejected file reports at most this many problems.</summary>
    public const int MaxProblemsReported = 20;
}

/// <summary>Bound to <c>Assessments:Import</c>.</summary>
public sealed class AssessmentImportOptions
{
    public const string Section = "Assessments:Import";

    public long MaxFileBytes { get; set; } = 64 * 1024 * 1024;
    public int MaxObservations { get; set; } = 20_000;
}

/// <summary>Why a file was rejected. Codes are part of the API contract.</summary>
public static class ImportProblemCodes
{
    public const string MalformedJson = "malformed_json";
    public const string NotAnArray = "not_an_array";
    public const string NoObservations = "no_observations";
    public const string FileTooLarge = "file_too_large";
    public const string TooManyObservations = "too_many_observations";
    public const string MissingField = "missing_field";
    public const string InvalidField = "invalid_field";
    public const string UnsupportedClass = "unsupported_class";
    public const string UnsupportedProwlerVersion = "unsupported_prowler_version";
    public const string UnsupportedOcsfVersion = "unsupported_ocsf_version";
    public const string UnsupportedProvider = "unsupported_provider";
    public const string ProviderMismatch = "provider_mismatch";
    public const string CheckIdMismatch = "check_id_mismatch";
    public const string ResourceCount = "resource_count";
    public const string LocationMismatch = "location_mismatch";
    public const string UnknownResult = "unknown_result";
    public const string MixedScanTimes = "mixed_scan_times";
    public const string InFileConflict = "in_file_conflict";
    public const string ConflictingObservation = "conflicting_observation";
}
