namespace K9.Api.Assessments;

public enum FindingStatus
{
    Open,
    Fixed,
}

/// <summary>What the lifecycle needs from one stored observation.</summary>
public sealed record ObservationFact(long Id, DateTimeOffset ScanTime, CheckResult Result, bool Muted);

/// <summary>A finding's current state, and the observations that explain it.</summary>
/// <param name="DecisiveObservationId">The latest conclusive observation: the one that decided the status.</param>
/// <param name="OpenSince">Start of the current (or, if fixed, the last) open period.</param>
/// <param name="Reopened">Open again after having been fixed.</param>
/// <param name="NeedsReview">The newest observation is not conclusive (MANUAL, MUTED or a muted PASS).</param>
/// <param name="MutedInSource">The newest observation is muted in Prowler.</param>
public sealed record FindingState(
    FindingStatus Status,
    long DecisiveObservationId,
    long LatestObservationId,
    DateTimeOffset OpenSince,
    DateTimeOffset? FixedAt,
    bool Reopened,
    bool NeedsReview,
    bool MutedInSource);

/// <summary>
/// Derives a finding's state from its complete observation history. A pure function of the
/// set of observations: the order they were imported in never matters.
/// </summary>
public static class FindingLifecycle
{
    /// <summary>
    /// Null when the identity has never failed (a PASS baseline is not a finding). Scan
    /// times must be unique within one history; the database guarantees that.
    /// </summary>
    public static FindingState? Derive(IReadOnlyCollection<ObservationFact> history) =>
        throw new NotImplementedException("PR (f): FindingLifecycle.Derive is not implemented yet.");
}
