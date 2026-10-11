namespace K9.Api.Organizations;

/// <summary>Roles within one organization, ordered from least to most privileged.</summary>
public enum OrganizationRole
{
    Viewer = 0,
    Analyst = 1,
    Admin = 2,
    Owner = 3,
}
