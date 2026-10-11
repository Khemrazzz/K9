using K9.Api.Organizations;

namespace K9.Api.Tenancy;

/// <summary>
/// Who is calling and which organization the request is acting in. Scoped per request.
/// The values are pushed into every database connection and enforced by Postgres
/// row-level security, so they are only ever set from verified sources: the user from a
/// validated token, the organization after a membership check.
/// </summary>
public sealed class RequestContext
{
    public Guid? UserId { get; private set; }
    public Guid? OrganizationId { get; private set; }
    public OrganizationRole? OrganizationRole { get; private set; }

    /// <summary>Increments whenever the user or organization changes.</summary>
    public int Version { get; private set; }

    public void SignIn(Guid userId)
    {
        if (UserId is not null && UserId != userId)
        {
            throw new InvalidOperationException("The request is already bound to a different user.");
        }
        if (UserId != userId)
        {
            UserId = userId;
            Version++;
        }
    }

    public void EnterOrganization(Guid organizationId, OrganizationRole role)
    {
        if (UserId is null)
        {
            throw new InvalidOperationException("Cannot enter an organization without a signed-in user.");
        }
        if (OrganizationId is not null && OrganizationId != organizationId)
        {
            throw new InvalidOperationException("The request is already bound to a different organization.");
        }
        if (OrganizationId != organizationId)
        {
            OrganizationId = organizationId;
            Version++;
        }
        OrganizationRole = role;
    }
}
