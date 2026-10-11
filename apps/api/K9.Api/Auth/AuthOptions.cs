using System.ComponentModel.DataAnnotations;

namespace K9.Api.Auth;

public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    /// <summary>
    /// The OIDC issuer exactly as it appears in the token's <c>iss</c> claim,
    /// e.g. <c>http://localhost:8081/realms/k9</c>.
    /// </summary>
    [Required, Url]
    public string Authority { get; set; } = "";

    /// <summary>
    /// Optional discovery document URL. Set it when the API reaches the identity
    /// provider on a different address than the public issuer, e.g. inside Docker:
    /// <c>http://keycloak:8080/realms/k9/.well-known/openid-configuration</c>.
    /// </summary>
    [Url]
    public string? MetadataAddress { get; set; }

    [Required]
    public string Audience { get; set; } = "k9-api";

    public bool RequireHttpsMetadata { get; set; } = true;
}
