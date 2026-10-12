using System.Text.Json;
using System.Text.RegularExpressions;
using K9.Api.Data;
using K9.Api.Organizations;
using Microsoft.EntityFrameworkCore;

namespace K9.Api.Audit;

public sealed record AuditEventResponse(
    long Id,
    DateTimeOffset OccurredAt,
    string Action,
    string Outcome,
    Guid? ActorUserId,
    string? ActorEmail,
    string? ResourceType,
    string? ResourceId,
    string CorrelationId,
    string? SourceIp,
    JsonElement? Details);

public sealed record AuditPage(IReadOnlyList<AuditEventResponse> Items, long? NextCursor);

public static partial class AuditEndpoints
{
    private const int DefaultLimit = 50;
    private const int MaxLimit = 200;
    private static readonly string[] Outcomes = ["success", "denied", "failure"];

    [GeneratedRegex(@"^[a-z][a-z_]*(\.[a-z][a-z_]*)+$")]
    private static partial Regex ActionPattern();

    public static IEndpointRouteBuilder MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet($"/api/organizations/{{{OrganizationPolicies.RouteValue}:guid}}/audit-events", List)
            .RequireAuthorization(OrganizationPolicies.Admin);
        return app;
    }

    /// <summary>
    /// The organization's audit events, newest first. Page with <c>before</c> set to the
    /// previous page's <c>nextCursor</c>. Row-level security limits rows to this organization
    /// in addition to the filter below.
    /// </summary>
    private static async Task<IResult> List(
        Guid organizationId,
        K9DbContext db,
        AuditLog audit,
        CancellationToken ct,
        int? limit = null,
        long? before = null,
        string? action = null,
        string? outcome = null,
        Guid? actorUserId = null,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null)
    {
        var errors = new Dictionary<string, string[]>();
        if (limit is < 1 or > MaxLimit)
        {
            errors["limit"] = [$"Must be between 1 and {MaxLimit}."];
        }
        if (before is < 1)
        {
            errors["before"] = ["Must be a cursor returned by a previous page."];
        }
        if (action is not null && (action.Length > 64 || !ActionPattern().IsMatch(action)))
        {
            errors["action"] = ["Must be an action name such as membership.add."];
        }
        if (outcome is not null && !Outcomes.Contains(outcome))
        {
            errors["outcome"] = ["Must be success, denied or failure."];
        }
        if (from is not null && to is not null && from > to)
        {
            errors["from"] = ["Must not be after 'to'."];
        }
        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        var pageSize = limit ?? DefaultLimit;
        var query = db.AuditEvents.Where(a => a.OrganizationId == organizationId);
        if (before is { } cursor)
        {
            query = query.Where(a => a.Id < cursor);
        }
        if (action is not null)
        {
            query = query.Where(a => a.Action == action);
        }
        if (outcome is not null)
        {
            query = query.Where(a => a.Outcome == outcome);
        }
        if (actorUserId is { } actor)
        {
            query = query.Where(a => a.ActorUserId == actor);
        }
        if (from is { } start)
        {
            query = query.Where(a => a.OccurredAt >= start);
        }
        if (to is { } end)
        {
            query = query.Where(a => a.OccurredAt <= end);
        }

        var rows = await query
            .OrderByDescending(a => a.Id)
            .Take(pageSize + 1)
            .Select(a => new
            {
                Event = a,
                // Visible only for users who are still members of this organization.
                ActorEmail = db.Users.Where(u => u.Id == a.ActorUserId).Select(u => u.Email).FirstOrDefault(),
            })
            .ToListAsync(ct);

        var items = rows.Take(pageSize).Select(r => new AuditEventResponse(
            r.Event.Id,
            r.Event.OccurredAt,
            r.Event.Action,
            r.Event.Outcome,
            r.Event.ActorUserId,
            r.ActorEmail,
            r.Event.ResourceType,
            r.Event.ResourceId,
            r.Event.CorrelationId,
            r.Event.SourceIp?.ToString(),
            r.Event.Details is null ? null : JsonDocument.Parse(r.Event.Details).RootElement.Clone())).ToList();

        // Reading the audit log is itself audited, and fails closed.
        await audit.RecordAsync(
            new AuditEvent(AuditActions.AuditRead, AuditOutcome.Success)
            {
                OrganizationId = organizationId,
                ResourceType = "audit_log",
                ResourceId = organizationId.ToString(),
            },
            ct);

        return Results.Ok(new AuditPage(items, rows.Count > pageSize ? items[^1].Id : null));
    }
}
