using K9.Api.Data;
using K9.Api.Tenancy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace K9.Api.Organizations;

/// <summary>
/// Requires the caller to hold at least <see cref="Minimum"/> in the organization named by
/// the <c>{organizationId}</c> route value. On success the request enters that organization.
/// </summary>
public sealed record OrganizationRoleRequirement(OrganizationRole Minimum) : IAuthorizationRequirement;

public static class OrganizationPolicies
{
    public const string Viewer = "org:viewer";
    public const string Analyst = "org:analyst";
    public const string Admin = "org:admin";
    public const string Owner = "org:owner";

    public const string RouteValue = "organizationId";

    public static AuthorizationBuilder AddOrganizationPolicies(this AuthorizationBuilder builder) => builder
        .AddPolicy(Viewer, p => p.RequireAuthenticatedUser().AddRequirements(new OrganizationRoleRequirement(OrganizationRole.Viewer)))
        .AddPolicy(Analyst, p => p.RequireAuthenticatedUser().AddRequirements(new OrganizationRoleRequirement(OrganizationRole.Analyst)))
        .AddPolicy(Admin, p => p.RequireAuthenticatedUser().AddRequirements(new OrganizationRoleRequirement(OrganizationRole.Admin)))
        .AddPolicy(Owner, p => p.RequireAuthenticatedUser().AddRequirements(new OrganizationRoleRequirement(OrganizationRole.Owner)));
}

/// <summary>
/// The organization ID in the URL is only a request. Membership is looked up from the
/// database for the authenticated user; nothing the client sends is trusted on its own.
/// </summary>
public sealed class OrganizationRoleHandler(K9DbContext db, RequestContext context)
    : AuthorizationHandler<OrganizationRoleRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext authorization, OrganizationRoleRequirement requirement)
    {
        if (authorization.Resource is not HttpContext http
            || context.UserId is not { } userId
            || http.GetRouteValue(OrganizationPolicies.RouteValue) is not string raw
            || !Guid.TryParse(raw, out var organizationId))
        {
            return;
        }

        var role = await db.Memberships
            .Where(m => m.OrganizationId == organizationId && m.UserId == userId)
            .Select(m => (OrganizationRole?)m.Role)
            .SingleOrDefaultAsync(http.RequestAborted);

        if (role is { } held && held >= requirement.Minimum)
        {
            context.EnterOrganization(organizationId, held);
            authorization.Succeed(requirement);
        }
    }
}
