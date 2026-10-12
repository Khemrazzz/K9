using K9.Api.Data;
using K9.Api.Organizations;
using K9.Api.Tenancy;
using K9.Api.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace K9.Api.Tests;

/// <summary>
/// Tenant context inside explicit transactions, savepoints, raw SQL and failures. Postgres
/// reverts set_config on rollback, so these pin down that the interceptor re-applies it.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class TransactionContextTests(K9ApiFactory api)
{
    [Fact]
    public async Task Context_set_inside_a_transaction_survives_its_rollback()
    {
        var (context, db) = Create();
        await using var _ = db;
        await db.Database.OpenConnectionAsync();

        await using (var transaction = await db.Database.BeginTransactionAsync())
        {
            context.EnterOrganization(Guid.NewGuid(), OrganizationRole.Viewer);
            Assert.Equal(context.OrganizationId.ToString(), await Setting(db, "k9.organization_id"));
            await transaction.RollbackAsync();
        }

        Assert.Equal(context.OrganizationId.ToString(), await Setting(db, "k9.organization_id"));
        Assert.Equal(context.UserId.ToString(), await Setting(db, "k9.user_id"));
    }

    [Fact]
    public async Task Context_survives_a_transaction_disposed_without_commit()
    {
        var (context, db) = Create();
        await using var _ = db;
        await db.Database.OpenConnectionAsync();

        await using (await db.Database.BeginTransactionAsync())
        {
            context.EnterOrganization(Guid.NewGuid(), OrganizationRole.Viewer);
            await Setting(db, "k9.organization_id");
        }

        Assert.Equal(context.OrganizationId.ToString(), await Setting(db, "k9.organization_id"));
    }

    [Fact]
    public async Task Context_survives_a_rollback_to_savepoint()
    {
        var (context, db) = Create();
        await using var _ = db;
        await using var transaction = await db.Database.BeginTransactionAsync();
        await Setting(db, "k9.user_id");
        await transaction.CreateSavepointAsync("before_org");

        context.EnterOrganization(Guid.NewGuid(), OrganizationRole.Viewer);
        Assert.Equal(context.OrganizationId.ToString(), await Setting(db, "k9.organization_id"));
        await transaction.RollbackToSavepointAsync("before_org");

        Assert.Equal(context.OrganizationId.ToString(), await Setting(db, "k9.organization_id"));
    }

    [Fact]
    public async Task Context_survives_a_failed_statement_and_rollback()
    {
        var (context, db) = Create();
        await using var _ = db;
        await db.Database.OpenConnectionAsync();

        await using (var transaction = await db.Database.BeginTransactionAsync())
        {
            context.EnterOrganization(Guid.NewGuid(), OrganizationRole.Viewer);
            await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlAsync($"SELECT 1/0"));
            await transaction.RollbackAsync();
        }

        Assert.Equal(context.OrganizationId.ToString(), await Setting(db, "k9.organization_id"));
    }

    [Fact]
    public async Task Raw_sql_and_database_functions_run_with_the_current_context()
    {
        var (context, db) = Create();
        await using var _ = db;
        context.EnterOrganization(Guid.NewGuid(), OrganizationRole.Viewer);

        var viaFunction = await db.Database.SqlQuery<Guid?>($"SELECT k9_current_organization_id() AS \"Value\"").SingleAsync();
        Assert.Equal(context.OrganizationId, viaFunction);
    }

    [Fact]
    public async Task Raw_ado_net_commands_see_only_what_ef_last_applied()
    {
        var (context, db) = Create();
        await using var _ = db;
        await db.Database.OpenConnectionAsync();
        context.EnterOrganization(Guid.NewGuid(), OrganizationRole.Viewer);

        // Bypassing EF bypasses the interceptor: this command still sees no organization.
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT current_setting('k9.organization_id', true)";
        Assert.Equal("", (string?)await command.ExecuteScalarAsync());
    }

    private (RequestContext Context, K9DbContext Db) Create()
    {
        var context = new RequestContext();
        context.SignIn(Guid.NewGuid());
        var options = new DbContextOptionsBuilder<K9DbContext>();
        K9DbContext.Configure(options, api.AppConnectionString);
        options.AddInterceptors(new TenantContextInterceptor(context));
        return (context, new K9DbContext(options.Options));
    }

    private static Task<string> Setting(K9DbContext db, string name) =>
        db.Database.SqlQuery<string>($"SELECT coalesce(current_setting({name}, true), '') AS \"Value\"").SingleAsync();
}
