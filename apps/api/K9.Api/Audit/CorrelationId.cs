using Microsoft.AspNetCore.Diagnostics;

namespace K9.Api.Audit;

/// <summary>
/// A server-generated ID per request, returned as <c>X-Correlation-Id</c> and stored with
/// every audit event and log line. Client-supplied correlation or trace headers are never
/// used, so a caller cannot make its requests look like someone else's.
/// </summary>
public static class CorrelationId
{
    public const string HeaderName = "X-Correlation-Id";
    private const string ItemName = "k9.correlation-id";

    public static string Get(HttpContext? http) =>
        http?.Items[ItemName] as string ?? "none";

    public static IApplicationBuilder UseK9CorrelationId(this IApplicationBuilder app) =>
        app.Use(async (http, next) =>
        {
            var id = Guid.CreateVersion7().ToString("N");
            http.Items[ItemName] = id;
            http.Response.Headers[HeaderName] = id;

            var logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("K9.Request");
            using (logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = id }))
            {
                await next(http);
            }
        });
}

/// <summary>
/// A security-relevant change that cannot be audited is not performed: its transaction is
/// rolled back and the caller gets 503.
/// </summary>
public sealed class AuditUnavailableHandler(IProblemDetailsService problemDetails, ILogger<AuditUnavailableHandler> logger)
    : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext http, Exception exception, CancellationToken cancellationToken)
    {
        if (exception is not AuditUnavailableException)
        {
            return false;
        }

        logger.LogError(exception.InnerException, "Request refused: audit log unavailable, correlation {CorrelationId}", CorrelationId.Get(http));
        http.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        return await problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = http,
            ProblemDetails =
            {
                Status = StatusCodes.Status503ServiceUnavailable,
                Title = "Audit log unavailable",
                Detail = "The action was not performed because it could not be recorded in the audit log.",
            },
        });
    }
}
