namespace K9.Api.Assessments;

/// <summary>
/// Reads and validates a Prowler OCSF file without buffering the raw document: findings
/// are parsed one at a time, and reading stops at the configured byte and observation limits.
/// </summary>
public static class ProwlerOcsfReader
{
    /// <summary>
    /// Validates the whole file. Returns observations only if every finding is valid;
    /// otherwise the (bounded) problems. Identical in-file duplicates are collapsed;
    /// contradictory ones are a problem.
    /// </summary>
    public static Task<ReadResult> ReadAsync(Stream utf8Json, AssessmentImportOptions limits, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException("PR (f): ProwlerOcsfReader.ReadAsync is not implemented yet.");
}
