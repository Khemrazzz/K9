using System.Net.Http.Headers;
using DotNet.Testcontainers.Builders;
using K9.Api.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Npgsql;
using Testcontainers.PostgreSql;

namespace K9.Api.Tests.Infrastructure;

/// <summary>
/// Runs the API against a real Postgres built by the same init script as docker compose,
/// with migrations applied as k9_owner and the API connected as k9_app.
/// </summary>
public sealed class K9ApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private const string OwnerPassword = "test-owner-password";
    private const string AppPassword = "test-app-password";

    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:17.6-alpine")
        .WithEnvironment("K9_OWNER_PASSWORD", OwnerPassword)
        .WithEnvironment("K9_APP_PASSWORD", AppPassword)
        .WithEnvironment("KEYCLOAK_DB_PASSWORD", "unused")
        .WithResourceMapping(new FileInfo(Path.Combine(RepoRoot(), "infrastructure", "postgres", "init", "01-databases.sh")), "/docker-entrypoint-initdb.d/")
        // During init Postgres only listens on a Unix socket; wait for TCP, which comes up
        // after the init scripts have run.
        .WithWaitStrategy(Wait.ForUnixContainer().UntilCommandIsCompleted("pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "k9"))
        .Build();

    public string AppConnectionString => ConnectionString("k9_app", AppPassword);
    public string SuperuserConnectionString => ConnectionString("postgres", "postgres");
    public string OwnerConnectionString => ConnectionString("k9_owner", OwnerPassword);

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:K9Migrations"] = OwnerConnectionString })
            .Build();
        if (await Migrator.RunAsync(configuration) != 0)
        {
            throw new InvalidOperationException("Migrations failed.");
        }
    }

    public new async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _postgres.DisposeAsync();
    }

    public HttpClient ClientFor(TestUser user) => ClientWithToken(TestTokens.For(user));

    public HttpClient ClientWithToken(string token)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:K9", AppConnectionString);
        builder.UseSetting("Auth:Authority", TestTokens.Issuer);
        builder.UseSetting("Auth:Audience", TestTokens.Audience);
        // Small enough for tests to exceed cheaply; the fixtures are far below both.
        builder.UseSetting("Assessments:Import:MaxFileBytes", TestLimits.MaxFileBytes.ToString());
        builder.UseSetting("Assessments:Import:MaxObservations", TestLimits.MaxObservations.ToString());

        builder.ConfigureTestServices(services =>
        {
            // Replace only the source of signing keys (normally Keycloak's JWKS endpoint).
            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                var configuration = new OpenIdConnectConfiguration { Issuer = TestTokens.Issuer };
                configuration.SigningKeys.Add(TestTokens.SigningKey);
                options.Configuration = configuration;
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
            });
        });
    }

    private string ConnectionString(string username, string password) =>
        new NpgsqlConnectionStringBuilder
        {
            Host = _postgres.Hostname,
            Port = _postgres.GetMappedPublicPort(5432),
            Database = "k9",
            Username = username,
            Password = password,
            // Small pool so tests exercise connection reuse across requests and users.
            MaxPoolSize = 4,
        }.ConnectionString;

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "compose.yaml")))
            {
                return dir.FullName;
            }
        }
        throw new InvalidOperationException("Could not find the repository root (compose.yaml).");
    }
}

public static class TestLimits
{
    public const long MaxFileBytes = 2 * 1024 * 1024;
    public const int MaxObservations = 100;
}

[CollectionDefinition(Name)]
public sealed class ApiCollection : ICollectionFixture<K9ApiFactory>
{
    public const string Name = "api";
}
