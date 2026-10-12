using K9.Api.Audit;
using K9.Api.Data;
using K9.Api.Tenancy;
using Microsoft.EntityFrameworkCore;

namespace K9.Api.Organizations;

public sealed record CreateOrganizationRequest(string? Name);
public sealed record AddMemberRequest(string? Email, OrganizationRole? Role);
public sealed record ChangeRoleRequest(OrganizationRole? Role);
public sealed record OrganizationResponse(Guid Id, string Name, DateTimeOffset CreatedAt, OrganizationRole Role);
public sealed record MemberResponse(Guid UserId, string? Email, string? DisplayName, OrganizationRole Role, DateTimeOffset JoinedAt);
public sealed record MeResponse(Guid Id, string? Email, string? DisplayName, IReadOnlyList<OrganizationResponse> Organizations);

public static class OrganizationEndpoints
{
    private const int MaxNameLength = 200;

    public static IEndpointRouteBuilder MapOrganizationEndpoints(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api");

        api.MapGet("/me", GetMe);
        api.MapPost("/organizations", CreateOrganization);

        var organization = api.MapGroup($"/organizations/{{{OrganizationPolicies.RouteValue}:guid}}");
        organization.MapGet("", GetOrganization).RequireAuthorization(OrganizationPolicies.Viewer);
        organization.MapGet("/members", ListMembers).RequireAuthorization(OrganizationPolicies.Viewer);
        organization.MapPost("/members", AddMember).RequireAuthorization(OrganizationPolicies.Admin);
        organization.MapPatch("/members/{userId:guid}", ChangeRole).RequireAuthorization(OrganizationPolicies.Admin);
        // Viewer: members may remove themselves; removing others needs Admin (checked inside).
        organization.MapDelete("/members/{userId:guid}", RemoveMember).RequireAuthorization(OrganizationPolicies.Viewer);

        return app;
    }

    private static async Task<MeResponse> GetMe(K9DbContext db, RequestContext context, CancellationToken ct)
    {
        var userId = context.UserId!.Value;
        var user = await db.Users.SingleAsync(u => u.Id == userId, ct);
        var organizations = await db.Memberships
            .Where(m => m.UserId == userId)
            .OrderBy(m => m.Organization.Name)
            .Select(m => new OrganizationResponse(m.Organization.Id, m.Organization.Name, m.Organization.CreatedAt, m.Role))
            .ToListAsync(ct);
        return new MeResponse(user.Id, user.Email, user.DisplayName, organizations);
    }

    private static async Task<IResult> CreateOrganization(
        CreateOrganizationRequest request, K9DbContext db, RequestContext context, AuditLog audit, CancellationToken ct)
    {
        var name = request.Name?.Trim();
        if (string.IsNullOrEmpty(name) || name.Length > MaxNameLength)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["name"] = [$"Name is required and must be at most {MaxNameLength} characters."],
            });
        }

        var now = DateTimeOffset.UtcNow;
        var organization = new Organization { Id = Guid.CreateVersion7(), Name = name, CreatedAt = now };
        organization.Memberships.Add(new Membership
        {
            OrganizationId = organization.Id,
            UserId = context.UserId!.Value,
            Role = OrganizationRole.Owner,
            CreatedAt = now,
        });

        // Row-level security only accepts rows for the request's organization, so the
        // request enters the new organization before inserting it.
        context.EnterOrganization(organization.Id, OrganizationRole.Owner);

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        db.Organizations.Add(organization);
        await db.SaveChangesAsync(ct);
        await audit.RecordAsync(
            new AuditEvent(AuditActions.OrganizationCreate, AuditOutcome.Success)
            {
                OrganizationId = organization.Id,
                ResourceType = "organization",
                ResourceId = organization.Id.ToString(),
            },
            ct);
        await transaction.CommitAsync(ct);

        return Results.Created(
            $"/api/organizations/{organization.Id}",
            new OrganizationResponse(organization.Id, organization.Name, organization.CreatedAt, OrganizationRole.Owner));
    }

    private static async Task<OrganizationResponse> GetOrganization(
        Guid organizationId, K9DbContext db, RequestContext context, CancellationToken ct)
    {
        var organization = await db.Organizations.SingleAsync(o => o.Id == organizationId, ct);
        return new OrganizationResponse(organization.Id, organization.Name, organization.CreatedAt, context.OrganizationRole!.Value);
    }

    private static async Task<List<MemberResponse>> ListMembers(Guid organizationId, K9DbContext db, CancellationToken ct) =>
        await db.Memberships
            .Where(m => m.OrganizationId == organizationId)
            .OrderBy(m => m.CreatedAt)
            .Select(m => new MemberResponse(m.UserId, m.User.Email, m.User.DisplayName, m.Role, m.CreatedAt))
            .ToListAsync(ct);

    private static async Task<IResult> AddMember(
        Guid organizationId, AddMemberRequest request, K9DbContext db, RequestContext context, AuditLog audit, CancellationToken ct)
    {
        var email = request.Email?.Trim();
        if (string.IsNullOrEmpty(email) || request.Role is not { } role || !Enum.IsDefined(role))
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["request"] = ["Email and a valid role are required."],
            });
        }

        var attempt = new MembershipAudit(audit, AuditActions.MembershipAdd, organizationId, ct);
        if (role > context.OrganizationRole)
        {
            await attempt.DeniedAsync(null, "role_above_own", ("role", role.ToString()));
            return Forbidden("You cannot grant a role higher than your own.");
        }

        // SECURITY DEFINER lookup: the runtime role cannot read users outside its organizations.
        var userId = await db.Database
            .SqlQuery<Guid?>($"SELECT k9_find_user_id_by_email({email}) AS \"Value\"")
            .SingleAsync(ct);
        if (userId is null)
        {
            // The email is not recorded: it may belong to someone who is not a K9 user.
            await attempt.FailedAsync(null, "user_not_found");
            return Results.Problem(
                statusCode: StatusCodes.Status404NotFound,
                detail: "No K9 user with that email. They must sign in once before they can be added.");
        }

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        if (await db.Memberships.AnyAsync(m => m.OrganizationId == organizationId && m.UserId == userId, ct))
        {
            await transaction.RollbackAsync(ct);
            await attempt.FailedAsync(userId, "already_member");
            return Results.Problem(statusCode: StatusCodes.Status409Conflict, detail: "That user is already a member.");
        }

        var membership = new Membership
        {
            OrganizationId = organizationId,
            UserId = userId.Value,
            Role = role,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        db.Memberships.Add(membership);
        await db.SaveChangesAsync(ct);
        await attempt.SucceededAsync(userId.Value, ("role", role.ToString()));
        await transaction.CommitAsync(ct);

        return Results.Created(
            $"/api/organizations/{organizationId}/members",
            new MemberResponse(membership.UserId, email, null, role, membership.CreatedAt));
    }

    private static async Task<IResult> ChangeRole(
        Guid organizationId, Guid userId, ChangeRoleRequest request, K9DbContext db, RequestContext context, AuditLog audit, CancellationToken ct)
    {
        if (request.Role is not { } role || !Enum.IsDefined(role))
        {
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["role"] = ["A valid role is required."] });
        }

        var attempt = new MembershipAudit(audit, AuditActions.MembershipChangeRole, organizationId, ct);
        var caller = context.OrganizationRole!.Value;

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await LockOrganizationAsync(db, organizationId, ct);
        var membership = await db.Memberships.SingleOrDefaultAsync(m => m.OrganizationId == organizationId && m.UserId == userId, ct);
        if (membership is null)
        {
            return Results.Problem(statusCode: StatusCodes.Status404NotFound, detail: "That user is not a member.");
        }

        var previous = membership.Role;
        if (role > caller || previous > caller)
        {
            await transaction.RollbackAsync(ct);
            await attempt.DeniedAsync(userId, role > caller ? "role_above_own" : "target_above_own", ("role", role.ToString()), ("previous_role", previous.ToString()));
            return Forbidden("You cannot change a member to, or from, a role higher than your own.");
        }
        if (previous == role)
        {
            return Results.Ok(await MemberAsync(db, organizationId, userId, ct));
        }
        if (previous == OrganizationRole.Owner && await IsLastOwnerAsync(db, organizationId, ct))
        {
            await transaction.RollbackAsync(ct);
            await attempt.FailedAsync(userId, "last_owner", ("role", role.ToString()));
            return LastOwner();
        }

        membership.Role = role;
        await db.SaveChangesAsync(ct);
        await attempt.SucceededAsync(userId, ("role", role.ToString()), ("previous_role", previous.ToString()));
        await transaction.CommitAsync(ct);

        return Results.Ok(await MemberAsync(db, organizationId, userId, ct));
    }

    private static async Task<IResult> RemoveMember(
        Guid organizationId, Guid userId, K9DbContext db, RequestContext context, AuditLog audit, CancellationToken ct)
    {
        var attempt = new MembershipAudit(audit, AuditActions.MembershipRemove, organizationId, ct);
        var caller = context.OrganizationRole!.Value;
        var removingSelf = userId == context.UserId;

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await LockOrganizationAsync(db, organizationId, ct);
        var membership = await db.Memberships.SingleOrDefaultAsync(m => m.OrganizationId == organizationId && m.UserId == userId, ct);
        if (membership is null)
        {
            return Results.Problem(statusCode: StatusCodes.Status404NotFound, detail: "That user is not a member.");
        }

        if (!removingSelf && (caller < OrganizationRole.Admin || membership.Role > caller))
        {
            await transaction.RollbackAsync(ct);
            await attempt.DeniedAsync(userId, caller < OrganizationRole.Admin ? "requires_admin" : "target_above_own", ("role", membership.Role.ToString()));
            return Forbidden("You cannot remove this member.");
        }
        if (membership.Role == OrganizationRole.Owner && await IsLastOwnerAsync(db, organizationId, ct))
        {
            await transaction.RollbackAsync(ct);
            await attempt.FailedAsync(userId, "last_owner");
            return LastOwner();
        }

        db.Memberships.Remove(membership);
        await db.SaveChangesAsync(ct);
        await attempt.SucceededAsync(userId, ("role", membership.Role.ToString()), ("self", removingSelf ? "true" : "false"));
        await transaction.CommitAsync(ct);

        return Results.NoContent();
    }

    // Serializes membership changes per organization, so concurrent requests cannot each
    // see "another owner remains" and remove the last two owners together.
    private static Task LockOrganizationAsync(K9DbContext db, Guid organizationId, CancellationToken ct) =>
        db.Database
            .SqlQuery<Guid>($"SELECT id AS \"Value\" FROM organizations WHERE id = {organizationId} FOR UPDATE")
            .SingleAsync(ct);

    private static async Task<bool> IsLastOwnerAsync(K9DbContext db, Guid organizationId, CancellationToken ct) =>
        await db.Memberships.CountAsync(m => m.OrganizationId == organizationId && m.Role == OrganizationRole.Owner, ct) <= 1;

    private static Task<MemberResponse> MemberAsync(K9DbContext db, Guid organizationId, Guid userId, CancellationToken ct) =>
        db.Memberships
            .Where(m => m.OrganizationId == organizationId && m.UserId == userId)
            .Select(m => new MemberResponse(m.UserId, m.User.Email, m.User.DisplayName, m.Role, m.CreatedAt))
            .SingleAsync(ct);

    private static IResult Forbidden(string detail) =>
        Results.Problem(statusCode: StatusCodes.Status403Forbidden, detail: detail);

    private static IResult LastOwner() =>
        Results.Problem(statusCode: StatusCodes.Status409Conflict, detail: "An organization must keep at least one owner.");

    /// <summary>Audit helper for membership operations in the request's organization.</summary>
    private sealed class MembershipAudit(AuditLog audit, string action, Guid organizationId, CancellationToken ct)
    {
        // Success is recorded inside the change's transaction and fails closed.
        public Task SucceededAsync(Guid memberUserId, params (string Key, string Value)[] facts) =>
            audit.RecordAsync(Event(AuditOutcome.Success, memberUserId, null, facts), ct);

        // Refusals are recorded after rolling back; a failed write never changes the refusal.
        public Task DeniedAsync(Guid? memberUserId, string reason, params (string Key, string Value)[] facts) =>
            audit.TryRecordAsync(Event(AuditOutcome.Denied, memberUserId, reason, facts), ct);

        public Task FailedAsync(Guid? memberUserId, string reason, params (string Key, string Value)[] facts) =>
            audit.TryRecordAsync(Event(AuditOutcome.Failure, memberUserId, reason, facts), ct);

        private AuditEvent Event(AuditOutcome outcome, Guid? memberUserId, string? reason, (string Key, string Value)[] facts)
        {
            var details = facts.ToDictionary(f => f.Key, f => f.Value);
            if (reason is not null)
            {
                details["reason"] = reason;
            }
            return new AuditEvent(action, outcome)
            {
                OrganizationId = organizationId,
                ResourceType = "membership",
                ResourceId = memberUserId?.ToString(),
                Details = details,
            };
        }
    }
}
