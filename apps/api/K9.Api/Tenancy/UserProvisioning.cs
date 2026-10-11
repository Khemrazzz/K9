using System.Security.Claims;
using K9.Api.Auth;
using K9.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace K9.Api.Tenancy;

public static class UserProvisioning
{
    /// <summary>
    /// Maps the token's subject to a K9 user (creating it on first sign-in) and binds the
    /// request to that user. Runs after authentication, before authorization.
    /// </summary>
    public static IApplicationBuilder UseK9UserProvisioning(this IApplicationBuilder app) =>
        app.Use(async (http, next) =>
        {
            if (http.User.Identity?.IsAuthenticated == true)
            {
                var db = http.RequestServices.GetRequiredService<K9DbContext>();
                var context = http.RequestServices.GetRequiredService<RequestContext>();
                context.SignIn(await UpsertUserAsync(db, http.User, http.RequestAborted));
            }
            await next(http);
        });

    // k9_upsert_user is SECURITY DEFINER: the runtime role cannot write the users table directly.
    private static Task<Guid> UpsertUserAsync(K9DbContext db, ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        // The subject was validated with the token. Profile claims are only cleaned of control
        // characters here (Postgres text cannot hold NUL); the function validates the rest.
        var subject = user.FindFirst(K9Claims.Subject)!.Value;
        var email = WithoutControlCharacters(user.FindFirst(K9Claims.Email)?.Value);
        var name = WithoutControlCharacters(user.FindFirst(K9Claims.Name)?.Value);
        return db.Database
            .SqlQuery<Guid>($"SELECT k9_upsert_user({subject}, {email}, {name}) AS \"Value\"")
            .SingleAsync(cancellationToken);
    }

    private static string? WithoutControlCharacters(string? value) =>
        value is null || !value.Any(char.IsControl) ? value : string.Concat(value.Where(c => !char.IsControl(c)));
}
