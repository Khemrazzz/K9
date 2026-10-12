using System.Net;
using System.Net.Http.Json;
using K9.Api.Organizations;
using K9.Api.Tests.Infrastructure;

namespace K9.Api.Tests;

/// <summary>Role changes and removals: privilege ceilings, the last-owner rule and races.</summary>
[Collection(ApiCollection.Name)]
public sealed class MembershipManagementTests(K9ApiFactory api)
{
    [Fact]
    public async Task Admins_cannot_raise_anyone_to_owner_or_touch_an_owner()
    {
        var owner = await api.SignInAsync("Owner");
        var admin = await api.SignInAsync("Admin");
        var viewer = await api.SignInAsync("Viewer");
        var organizationId = await owner.CreateOrganizationAsync();
        await owner.AddMemberAsync(organizationId, admin, OrganizationRole.Admin);
        await owner.AddMemberAsync(organizationId, viewer, OrganizationRole.Viewer);

        Assert.Equal(HttpStatusCode.Forbidden, (await admin.ChangeRoleAsync(organizationId, viewer.Id, OrganizationRole.Owner)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.ChangeRoleAsync(organizationId, owner.Id, OrganizationRole.Viewer)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.RemoveMemberAsync(organizationId, owner.Id)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.ChangeRoleAsync(organizationId, viewer.Id, OrganizationRole.Analyst)).StatusCode);
    }

    [Fact]
    public async Task Viewers_cannot_manage_others_but_can_leave()
    {
        var owner = await api.SignInAsync("Owner");
        var viewer = await api.SignInAsync("Viewer");
        var other = await api.SignInAsync("Other");
        var organizationId = await owner.CreateOrganizationAsync();
        await owner.AddMemberAsync(organizationId, viewer, OrganizationRole.Viewer);
        await owner.AddMemberAsync(organizationId, other, OrganizationRole.Viewer);

        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.ChangeRoleAsync(organizationId, other.Id, OrganizationRole.Viewer)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.RemoveMemberAsync(organizationId, other.Id)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await viewer.RemoveMemberAsync(organizationId, viewer.Id)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.Client.GetAsync($"/api/organizations/{organizationId}")).StatusCode);
    }

    [Fact]
    public async Task The_last_owner_cannot_be_demoted_or_removed()
    {
        var owner = await api.SignInAsync("Owner");
        var organizationId = await owner.CreateOrganizationAsync();

        Assert.Equal(HttpStatusCode.Conflict, (await owner.ChangeRoleAsync(organizationId, owner.Id, OrganizationRole.Admin)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await owner.RemoveMemberAsync(organizationId, owner.Id)).StatusCode);
    }

    [Fact]
    public async Task Unknown_members_and_invalid_roles_are_rejected()
    {
        var owner = await api.SignInAsync("Owner");
        var organizationId = await owner.CreateOrganizationAsync();

        Assert.Equal(HttpStatusCode.NotFound, (await owner.ChangeRoleAsync(organizationId, Guid.NewGuid(), OrganizationRole.Viewer)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await owner.RemoveMemberAsync(organizationId, Guid.NewGuid())).StatusCode);
        foreach (var body in new[] { """{"role":"Root"}""", """{"role":42}""", "{}" })
        {
            var response = await owner.Client.PatchAsync(
                $"/api/organizations/{organizationId}/members/{owner.Id}",
                new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task Members_cannot_be_changed_through_another_organization()
    {
        var alice = await api.SignInAsync("Alice");
        var bob = await api.SignInAsync("Bob");
        var bobsColleague = await api.SignInAsync("Colleague");
        await alice.CreateOrganizationAsync();
        var globex = await bob.CreateOrganizationAsync();
        await bob.AddMemberAsync(globex, bobsColleague, OrganizationRole.Viewer);
        var acme = (await alice.Client.GetFromJsonAsync<MeResponse>("/api/me", Json.Options))!.Organizations.Single().Id;

        // Alice owns Acme; Bob's colleague belongs to Globex only.
        Assert.Equal(HttpStatusCode.NotFound, (await alice.ChangeRoleAsync(acme, bobsColleague.Id, OrganizationRole.Owner)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await alice.RemoveMemberAsync(acme, bobsColleague.Id)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await alice.RemoveMemberAsync(globex, bobsColleague.Id)).StatusCode);
    }

    [Fact]
    public async Task Concurrent_demotions_never_leave_an_organization_without_an_owner()
    {
        for (var round = 0; round < 5; round++)
        {
            var first = await api.SignInAsync("First");
            var second = await api.SignInAsync("Second");
            var organizationId = await first.CreateOrganizationAsync();
            await first.AddMemberAsync(organizationId, second, OrganizationRole.Owner);

            // Each owner demotes the other at the same moment.
            var results = await Task.WhenAll(
                first.ChangeRoleAsync(organizationId, second.Id, OrganizationRole.Admin),
                second.ChangeRoleAsync(organizationId, first.Id, OrganizationRole.Admin));

            Assert.Single(results, r => r.StatusCode == HttpStatusCode.OK);
            Assert.Single(results, r => r.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.Forbidden);

            var members = await first.Client.GetFromJsonAsync<List<MemberResponse>>($"/api/organizations/{organizationId}/members", Json.Options)
                ?? await second.Client.GetFromJsonAsync<List<MemberResponse>>($"/api/organizations/{organizationId}/members", Json.Options);
            Assert.Single(members!, m => m.Role == OrganizationRole.Owner);
        }
    }
}
