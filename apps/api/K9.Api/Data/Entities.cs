using K9.Api.Organizations;

namespace K9.Api.Data;

public sealed class Organization
{
    public Guid Id { get; init; }
    public required string Name { get; set; }
    public DateTimeOffset CreatedAt { get; init; }
    public List<Membership> Memberships { get; } = [];
}

/// <summary>
/// A person known to K9, keyed by the identity provider's subject. Rows are written only
/// by the <c>k9_upsert_user</c> database function, never directly by the API.
/// </summary>
public sealed class User
{
    public Guid Id { get; init; }
    public required string Subject { get; init; }
    public string? Email { get; init; }
    public string? DisplayName { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}

public sealed class Membership
{
    public Guid OrganizationId { get; init; }
    public Guid UserId { get; init; }
    public OrganizationRole Role { get; set; }
    public DateTimeOffset CreatedAt { get; init; }
    public Organization Organization { get; init; } = null!;
    public User User { get; init; } = null!;
}
