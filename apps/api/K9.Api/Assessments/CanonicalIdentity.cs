namespace K9.Api.Assessments;

/// <summary>
/// What K9 considers "the same check on the same resource". Prowler's finding UID and scan
/// ID are traceability metadata only. See docs/prowler-import-contract.md for why every
/// component is needed.
/// </summary>
public sealed record CanonicalIdentity(
    Guid OrganizationId,
    string Provider,
    string AccountUid,
    string CheckId,
    string Location,
    string ResourceUid,
    string ResourceName)
{
    public static CanonicalIdentity For(Guid organizationId, ParsedObservation observation) =>
        new(organizationId, observation.Provider, observation.AccountUid, observation.CheckId,
            observation.Location, observation.ResourceUid, observation.ResourceName);

    /// <summary>An unambiguous encoding of every component (a JSON array).</summary>
    public string CanonicalKey =>
        throw new NotImplementedException("PR (f): CanonicalIdentity.CanonicalKey is not implemented yet.");

    /// <summary>SHA-256 of <see cref="CanonicalKey"/>.</summary>
    public byte[] Hash =>
        throw new NotImplementedException("PR (f): CanonicalIdentity.Hash is not implemented yet.");
}
