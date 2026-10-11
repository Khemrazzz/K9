using K9.Api.Data;
using K9.Api.Tenancy;
using Microsoft.EntityFrameworkCore;

namespace K9.Api.Organizations;

public sealed record CreateOrganizationRequest(string? Name);
public sealed record AddMemberRequest(string? Email, OrganizationRole? Role);
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
        CreateOrganizationRequest request, K9DbContext db, RequestContext context, CancellationToken ct)
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
        db.Organizations.Add(organization);
        await db.SaveChangesAsync(ct);

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
        Guid organizationId, AddMemberRequest request, K9DbContext db, RequestContext context, CancellationToken ct)
    {
        var email = request.Email?.Trim();
        if (string.IsNullOrEmpty(email) || request.Role is not { } role || !Enum.IsDefined(role))
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["request"] = ["Email and a valid role are required."],
            });
        }
        if (role > context.OrganizationRole)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                detail: "You cannot grant a role higher than your own.");
        }

        // SECURITY DEFINER lookup: the runtime role cannot read users outside its organizations.
        var userId = await db.Database
            .SqlQuery<Guid?>($"SELECT k9_find_user_id_by_email({email}) AS \"Value\"")
            .SingleAsync(ct);
        if (userId is null)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status404NotFound,
                detail: "No K9 user with that email. They must sign in once before they can be added.");
        }

        if (await db.Memberships.AnyAsync(m => m.OrganizationId == organizationId && m.UserId == userId, ct))
        {
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

        return Results.Created(
            $"/api/organizations/{organizationId}/members",
            new MemberResponse(membership.UserId, email, null, role, membership.CreatedAt));
    }
}
