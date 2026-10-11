using K9.Api.Tenancy;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace K9.Api.Data;

public sealed class K9DbContext(DbContextOptions<K9DbContext> options) : DbContext(options)
{
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Membership> Memberships => Set<Membership>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<Organization>(e =>
        {
            e.Property(o => o.Id).ValueGeneratedNever();
            e.Property(o => o.Name).HasMaxLength(200);
        });

        model.Entity<User>(e =>
        {
            e.Property(u => u.Id).ValueGeneratedNever();
            e.Property(u => u.Subject).HasMaxLength(255);
            e.Property(u => u.Email).HasMaxLength(320);
            e.Property(u => u.DisplayName).HasMaxLength(200);
            e.HasIndex(u => u.Subject).IsUnique();
            // Not unique: the identity provider owns email uniqueness. Lookups by email
            // treat duplicates as "not found".
            e.HasIndex(u => u.Email);
        });

        model.Entity<Membership>(e =>
        {
            e.HasKey(m => new { m.OrganizationId, m.UserId });
            e.Property(m => m.Role).HasConversion<string>().HasMaxLength(20);
            e.ToTable(t => t.HasCheckConstraint("ck_memberships_role", "role IN ('Viewer', 'Analyst', 'Admin', 'Owner')"));
            e.HasOne(m => m.Organization).WithMany(o => o.Memberships).HasForeignKey(m => m.OrganizationId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(m => m.User).WithMany().HasForeignKey(m => m.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(m => m.UserId);
        });
    }

    public static void Configure(DbContextOptionsBuilder options, string connectionString) =>
        options.UseNpgsql(connectionString).UseSnakeCaseNamingConvention();
}

public static class DataSetup
{
    public static IServiceCollection AddK9Data(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("K9");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException("ConnectionStrings:K9 is not configured. See the README.");
        }

        services.AddScoped<RequestContext>();
        services.AddScoped<TenantContextInterceptor>();
        services.AddDbContext<K9DbContext>((sp, options) =>
        {
            K9DbContext.Configure(options, connectionString);
            options.AddInterceptors(sp.GetRequiredService<TenantContextInterceptor>());
        });
        return services;
    }
}

/// <summary>Applies migrations as the schema-owning role. Invoked with <c>dotnet run -- migrate</c>.</summary>
public static class Migrator
{
    public static async Task<int> RunAsync(IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("K9Migrations");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            await Console.Error.WriteLineAsync("ConnectionStrings:K9Migrations is not configured. See the README.");
            return 1;
        }

        var options = new DbContextOptionsBuilder<K9DbContext>();
        K9DbContext.Configure(options, connectionString);
        await using var db = new K9DbContext(options.Options);
        await db.Database.MigrateAsync();
        Console.WriteLine("Database is up to date.");
        return 0;
    }
}

/// <summary>Lets <c>dotnet ef migrations add</c> build the model without a running app.</summary>
public sealed class DesignTimeK9DbContextFactory : IDesignTimeDbContextFactory<K9DbContext>
{
    public K9DbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<K9DbContext>();
        K9DbContext.Configure(options, "Host=localhost;Database=k9");
        return new K9DbContext(options.Options);
    }
}
