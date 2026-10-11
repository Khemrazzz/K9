using System.Text.Json.Serialization;
using K9.Api.Auth;
using K9.Api.Data;
using K9.Api.Organizations;
using K9.Api.Tenancy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

var builder = WebApplication.CreateBuilder(args);

if (args is ["migrate"])
{
    return await Migrator.RunAsync(builder.Configuration);
}

if (!builder.Environment.IsDevelopment())
{
    builder.Logging.ClearProviders();
    builder.Logging.AddJsonConsole(o =>
    {
        o.IncludeScopes = true;
        o.UseUtcTimestamp = true;
    });
}

builder.Services.AddK9Data(builder.Configuration);
builder.Services.AddK9Authentication(builder.Configuration);
builder.Services.AddScoped<IAuthorizationHandler, OrganizationRoleHandler>();
builder.Services.AddAuthorizationBuilder()
    // Every endpoint requires a valid access token unless it explicitly opts out.
    .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
    .AddOrganizationPolicies();

builder.Services.AddProblemDetails();
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddHealthChecks().AddDbContextCheck<K9DbContext>("database", tags: ["ready"]);

var app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseAuthentication();
app.UseK9UserProvisioning();
app.UseAuthorization();

app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();
app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = c => c.Tags.Contains("ready") }).AllowAnonymous();
app.MapOrganizationEndpoints();

await app.RunAsync();
return 0;

public partial class Program;
