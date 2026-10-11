using System.Net;
using System.Net.Http.Json;
using K9.Api.Organizations;
using K9.Api.Tests.Infrastructure;

namespace K9.Api.Tests;

[Collection(ApiCollection.Name)]
public sealed class AuthenticationTests(K9ApiFactory api)
{
    [Fact]
    public async Task Liveness_is_anonymous()
    {
        var response = await api.CreateClient().GetAsync("/health/live");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Readiness_checks_the_database()
    {
        var response = await api.CreateClient().GetAsync("/health/ready");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Request_without_token_is_rejected()
    {
        var response = await api.CreateClient().GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    public static TheoryData<string, Func<TestUser, string>> InvalidTokens => new()
    {
        { "wrong audience", u => TestTokens.For(u, audience: "some-other-api") },
        { "wrong issuer", u => TestTokens.For(u, issuer: "https://evil.example/realms/k9") },
        { "expired", u => TestTokens.For(u, lifetime: TimeSpan.FromMinutes(-5)) },
        { "signed by an untrusted key", u => TestTokens.For(u, key: TestTokens.UntrustedKey) },
        { "refresh token", u => TestTokens.For(u, tokenType: "Refresh") },
        { "ID token", u => TestTokens.For(u, tokenType: "ID") },
        { "no subject", u => TestTokens.For(u, includeSubject: false) },
        { "not a JWT", _ => "not-a-token" },
    };

    [Theory]
    [MemberData(nameof(InvalidTokens))]
    public async Task Invalid_token_is_rejected(string because, Func<TestUser, string> token)
    {
        var response = await api.ClientWithToken(token(TestUser.Create("Mallory"))).GetAsync("/api/me");
        Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"Expected 401 for a token that is {because}, got {(int)response.StatusCode}.");
    }

    [Fact]
    public async Task Valid_token_provisions_the_user_once()
    {
        var alice = TestUser.Create("Alice");
        var client = api.ClientFor(alice);

        var first = await client.GetFromJsonAsync<MeResponse>("/api/me", Json.Options);
        var second = await client.GetFromJsonAsync<MeResponse>("/api/me", Json.Options);

        Assert.NotNull(first);
        Assert.Equal(alice.Email, first.Email);
        Assert.Equal(alice.Name, first.DisplayName);
        Assert.Empty(first.Organizations);
        Assert.Equal(first.Id, second!.Id);
    }
}
