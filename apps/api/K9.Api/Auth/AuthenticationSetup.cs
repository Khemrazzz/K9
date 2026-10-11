using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace K9.Api.Auth;

public static class AuthenticationSetup
{
    // Matches users.subject. Keycloak subjects are UUIDs.
    private const int MaxSubjectLength = 255;

    public static IServiceCollection AddK9Authentication(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<AuthOptions>()
            .Bind(configuration.GetSection(AuthOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();

        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<AuthOptions>>((jwt, authOptions) =>
            {
                var auth = authOptions.Value;
                jwt.Authority = auth.Authority;
                if (!string.IsNullOrEmpty(auth.MetadataAddress))
                {
                    jwt.MetadataAddress = auth.MetadataAddress;
                }
                jwt.RequireHttpsMetadata = auth.RequireHttpsMetadata;
                jwt.MapInboundClaims = false;
                jwt.TokenValidationParameters = new TokenValidationParameters
                {
                    // The issuer is pinned to the configured public URL even when metadata is
                    // fetched from an internal address.
                    ValidIssuer = auth.Authority,
                    ValidAudience = auth.Audience,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                    ClockSkew = TimeSpan.FromSeconds(30),
                    NameClaimType = K9Claims.Subject,
                };
                jwt.Events = new JwtBearerEvents { OnTokenValidated = RejectNonAccessTokens };
            });

        return services;
    }

    // Keycloak marks access tokens with typ=Bearer. Refresh and ID tokens carry other
    // values and must never authenticate an API call.
    private static Task RejectNonAccessTokens(TokenValidatedContext context)
    {
        var principal = context.Principal;
        if (principal?.FindFirst(K9Claims.TokenType)?.Value != "Bearer")
        {
            context.Fail("Only access tokens are accepted.");
        }
        else if (principal.FindFirst(K9Claims.Subject)?.Value is not { Length: > 0 and <= MaxSubjectLength } subject
                 || subject.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)))
        {
            context.Fail("Token has a missing or malformed subject.");
        }
        return Task.CompletedTask;
    }
}

public static class K9Claims
{
    public const string Subject = "sub";
    public const string TokenType = "typ";
    public const string Email = "email";
    public const string Name = "name";
}
