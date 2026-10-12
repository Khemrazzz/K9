using K9.Api.Audit;
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
                jwt.Events = new JwtBearerEvents
                {
                    OnTokenValidated = RejectNonAccessTokens,
                    OnAuthenticationFailed = context => RecordRejection(context.HttpContext, ReasonFor(context.Exception)),
                };
            });

        return services;
    }

    // Keycloak marks access tokens with typ=Bearer. Refresh and ID tokens carry other
    // values and must never authenticate an API call.
    private static async Task RejectNonAccessTokens(TokenValidatedContext context)
    {
        var principal = context.Principal;
        if (principal?.FindFirst(K9Claims.TokenType)?.Value != "Bearer")
        {
            context.Fail("Only access tokens are accepted.");
            await RecordRejection(context.HttpContext, "wrong_token_type");
        }
        else if (principal.FindFirst(K9Claims.Subject)?.Value is not { Length: > 0 and <= MaxSubjectLength } subject
                 || subject.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)))
        {
            context.Fail("Token has a missing or malformed subject.");
            await RecordRejection(context.HttpContext, "invalid_subject");
        }
    }

    // Records that a presented token was refused. Nothing from the token is stored, not even
    // its subject: an invalid token's claims are attacker-controlled. The reason is a fixed
    // category, never the token or the validator's message.
    private static Task RecordRejection(HttpContext http, string reason) =>
        http.RequestServices.GetRequiredService<AuditLog>().TryRecordAsync(
            new AuditEvent(AuditActions.TokenRejected, AuditOutcome.Failure)
            {
                Details = new Dictionary<string, string> { ["reason"] = reason },
            },
            http.RequestAborted);

    private static string ReasonFor(Exception exception) => exception switch
    {
        SecurityTokenExpiredException => "expired",
        SecurityTokenNotYetValidException => "not_yet_valid",
        SecurityTokenInvalidAudienceException => "invalid_audience",
        SecurityTokenInvalidIssuerException => "invalid_issuer",
        SecurityTokenSignatureKeyNotFoundException or SecurityTokenInvalidSignatureException => "invalid_signature",
        SecurityTokenInvalidAlgorithmException => "invalid_algorithm",
        SecurityTokenMalformedException or ArgumentException => "malformed",
        InvalidOperationException => "validation_unavailable",
        _ => "invalid",
    };
}

public static class K9Claims
{
    public const string Subject = "sub";
    public const string TokenType = "typ";
    public const string Email = "email";
    public const string Name = "name";
}
