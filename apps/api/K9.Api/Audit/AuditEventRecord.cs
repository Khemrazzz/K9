using System.Net;

namespace K9.Api.Audit;

/// <summary>
/// One row of <c>audit_events</c>. Read-only for the API: rows are written only by the
/// <c>k9_record_audit_event</c> database function and can never be updated or deleted by
/// the runtime role.
/// </summary>
public sealed class AuditEventRecord
{
    public long Id { get; init; }
    /// <summary>Database clock at insert time; never supplied by the application.</summary>
    public DateTimeOffset OccurredAt { get; init; }
    /// <summary>Set only when the organization was verified for this request.</summary>
    public Guid? OrganizationId { get; init; }
    /// <summary>Taken from the request's verified identity inside the database, not passed in.</summary>
    public Guid? ActorUserId { get; init; }
    public required string Action { get; init; }
    public required string Outcome { get; init; }
    public string? ResourceType { get; init; }
    public string? ResourceId { get; init; }
    public required string CorrelationId { get; init; }
    public IPAddress? SourceIp { get; init; }
    /// <summary>Small JSON object of allow-listed fields built by the API, never request payloads.</summary>
    public string? Details { get; init; }
}
