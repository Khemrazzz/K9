using System.Text.Json;
using K9.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace K9.Api.Audit;

public enum AuditOutcome
{
    Success,
    Denied,
    Failure,
}

public static class AuditActions
{
    public const string TokenRejected = "auth.token_rejected";
    public const string OrganizationAccess = "authz.organization_access";
    public const string OrganizationCreate = "organization.create";
    public const string MembershipAdd = "membership.add";
    public const string MembershipChangeRole = "membership.change_role";
    public const string MembershipRemove = "membership.remove";
    public const string AuditRead = "audit.read";
}

/// <summary>
/// What happened. Who did it and which organization it belongs to are not part of the
/// event: the database takes them from the request's verified context.
/// </summary>
public sealed record AuditEvent(string Action, AuditOutcome Outcome)
{
    /// <summary>
    /// The organization the event belongs to. Accepted only if it is the organization this
    /// request entered, or, for a denial, one the actor is a member of.
    /// </summary>
    public Guid? OrganizationId { get; init; }
    public string? ResourceType { get; init; }
    public string? ResourceId { get; init; }
    /// <summary>Allow-listed facts only. Never tokens, secrets, passwords or request bodies.</summary>
    public IReadOnlyDictionary<string, string>? Details { get; init; }
}

public sealed class AuditUnavailableException(Exception inner)
    : Exception("The audit log could not be written.", inner);

public sealed class AuditLog(K9DbContext db, IHttpContextAccessor httpContextAccessor, ILogger<AuditLog> logger)
{
    /// <summary>
    /// Writes the event or throws <see cref="AuditUnavailableException"/>. Call it inside
    /// the transaction of the change it records, so neither commits without the other.
    /// </summary>
    public async Task RecordAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        var http = httpContextAccessor.HttpContext;
        var action = auditEvent.Action;
        var outcome = auditEvent.Outcome.ToString().ToLowerInvariant();
        var organizationId = auditEvent.OrganizationId;
        var resourceType = auditEvent.ResourceType;
        var resourceId = auditEvent.ResourceId;
        var correlationId = CorrelationId.Get(http);
        var sourceIp = http?.Connection.RemoteIpAddress?.ToString();
        var details = auditEvent.Details is { Count: > 0 } facts ? JsonSerializer.Serialize(facts) : null;

        try
        {
            await db.Database
                .SqlQuery<long>($"""
                    SELECT public.k9_record_audit_event(
                        {action}, {outcome}, {organizationId}, {resourceType}, {resourceId},
                        {correlationId}, {sourceIp}::inet, {details}::jsonb) AS "Value"
                    """)
                .SingleAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new AuditUnavailableException(exception);
        }
    }

    /// <summary>
    /// For requests that are being refused anyway (bad tokens, denied access). Never throws:
    /// a failed write is logged and the refusal stands.
    /// </summary>
    public async Task TryRecordAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        try
        {
            await RecordAsync(auditEvent, cancellationToken);
        }
        catch (AuditUnavailableException exception)
        {
            logger.LogError(
                exception.InnerException,
                "Audit write failed: {Action} {Outcome}, correlation {CorrelationId}",
                auditEvent.Action,
                auditEvent.Outcome,
                CorrelationId.Get(httpContextAccessor.HttpContext));
        }
    }
}
