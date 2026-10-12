namespace K9.Api.Assessments;

/// <summary>
/// Decides whether two observations of the same identity and scan time say the same thing.
/// Computed over an explicit, versioned allowlist of fields, so fields that change on every
/// export (scan ID, resource dumps, field order) never cause false conflicts.
/// </summary>
public static class ObservationFingerprint
{
    public const int CurrentVersion = 1;

    /// <summary>The fields version 1 covers, in canonical (sorted) order.</summary>
    public static readonly IReadOnlyList<string> Version1Fields = ["muted", "resource_type", "result", "severity_id", "status_detail"];

    /// <summary>Canonical JSON (sorted keys, no whitespace) of exactly the version's fields.</summary>
    public static string CanonicalContent(ParsedObservation observation, int version = CurrentVersion) =>
        throw new NotImplementedException("PR (f): ObservationFingerprint.CanonicalContent is not implemented yet.");

    /// <summary>SHA-256 over the version tag and the canonical content. Unknown versions throw.</summary>
    public static byte[] Compute(string canonicalContent, int version = CurrentVersion) =>
        throw new NotImplementedException("PR (f): ObservationFingerprint.Compute is not implemented yet.");
}
