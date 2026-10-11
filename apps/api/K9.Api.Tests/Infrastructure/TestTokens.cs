using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace K9.Api.Tests.Infrastructure;

/// <summary>A test user identity, unique per test so tests never share data.</summary>
public sealed record TestUser(string Subject, string Email, string Name)
{
    public static TestUser Create(string name)
    {
        var id = Guid.NewGuid().ToString("N")[..12];
        return new TestUser($"sub-{id}", $"{name.ToLowerInvariant()}-{id}@k9.test", name);
    }
}

/// <summary>
/// Issues tokens shaped like Keycloak access tokens, signed with a key the test API trusts
/// in place of Keycloak's. Everything else about validation is the production configuration.
/// </summary>
public static class TestTokens
{
    public const string Issuer = "https://idp.k9.test/realms/k9";
    public const string Audience = "k9-api";

    public static readonly RsaSecurityKey SigningKey = new(RSA.Create(2048)) { KeyId = "k9-test-key" };
    public static readonly RsaSecurityKey UntrustedKey = new(RSA.Create(2048)) { KeyId = "k9-test-key" };

    public static string For(
        TestUser user,
        string issuer = Issuer,
        string audience = Audience,
        string tokenType = "Bearer",
        TimeSpan? lifetime = null,
        SecurityKey? key = null,
        bool includeSubject = true)
    {
        var now = DateTime.UtcNow;
        var expires = now + (lifetime ?? TimeSpan.FromMinutes(5));
        var claims = new Dictionary<string, object>
        {
            ["typ"] = tokenType,
            ["azp"] = "k9-web",
            ["email"] = user.Email,
            ["name"] = user.Name,
        };
        if (includeSubject)
        {
            claims["sub"] = user.Subject;
        }

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Claims = claims,
            IssuedAt = expires < now ? expires.AddMinutes(-5) : now,
            NotBefore = expires < now ? expires.AddMinutes(-5) : now,
            Expires = expires,
            SigningCredentials = new SigningCredentials(key ?? SigningKey, SecurityAlgorithms.RsaSha256),
        });
    }
}
