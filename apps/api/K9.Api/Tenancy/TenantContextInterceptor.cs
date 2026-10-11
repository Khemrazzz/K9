using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace K9.Api.Tenancy;

/// <summary>
/// Copies the request's user and organization into Postgres session settings, which the
/// row-level security policies read through <c>k9_current_user_id()</c> and
/// <c>k9_current_organization_id()</c>.
/// </summary>
/// <remarks>
/// The settings are written when EF opens a connection, and again before any command if
/// <see cref="RequestContext"/> changed since they were last written, so a query never
/// runs with stale values. Empty values mean "no user / no organization" and make the
/// policies return no rows. Npgsql discards session state when a connection returns to
/// the pool (covered by ConnectionPoolingTests), so values never carry over between requests.
///
/// Session-level settings are used rather than SET LOCAL because EF runs most queries
/// outside an explicit transaction, where SET LOCAL would not outlive its own statement.
/// </remarks>
public sealed class TenantContextInterceptor(RequestContext context) : DbConnectionInterceptor, IDbCommandInterceptor
{
    private const string Sql =
        "SELECT set_config('k9.user_id', @user_id, false), set_config('k9.organization_id', @organization_id, false)";

    private DbConnection? _appliedConnection;
    private int _appliedVersion;

    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData) =>
        Apply(connection, transaction: null);

    public override Task ConnectionOpenedAsync(
        DbConnection connection, ConnectionEndEventData eventData, CancellationToken cancellationToken = default) =>
        ApplyAsync(connection, transaction: null, cancellationToken);

    public InterceptionResult<DbDataReader> ReaderExecuting(
        DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
    {
        EnsureCurrent(command);
        return result;
    }

    public async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
        DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
    {
        await EnsureCurrentAsync(command, cancellationToken);
        return result;
    }

    public InterceptionResult<object> ScalarExecuting(
        DbCommand command, CommandEventData eventData, InterceptionResult<object> result)
    {
        EnsureCurrent(command);
        return result;
    }

    public async ValueTask<InterceptionResult<object>> ScalarExecutingAsync(
        DbCommand command, CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
    {
        await EnsureCurrentAsync(command, cancellationToken);
        return result;
    }

    public InterceptionResult<int> NonQueryExecuting(
        DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
    {
        EnsureCurrent(command);
        return result;
    }

    public async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
        DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        await EnsureCurrentAsync(command, cancellationToken);
        return result;
    }

    private bool IsCurrent(DbCommand command) =>
        ReferenceEquals(command.Connection, _appliedConnection) && _appliedVersion == context.Version;

    private void EnsureCurrent(DbCommand command)
    {
        if (!IsCurrent(command))
        {
            Apply(command.Connection!, command.Transaction);
        }
    }

    private async Task EnsureCurrentAsync(DbCommand command, CancellationToken cancellationToken)
    {
        if (!IsCurrent(command))
        {
            await ApplyAsync(command.Connection!, command.Transaction, cancellationToken);
        }
    }

    private void Apply(DbConnection connection, DbTransaction? transaction)
    {
        var version = context.Version;
        using var command = CreateCommand(connection, transaction);
        command.ExecuteNonQuery();
        MarkApplied(connection, version);
    }

    private async Task ApplyAsync(DbConnection connection, DbTransaction? transaction, CancellationToken cancellationToken)
    {
        var version = context.Version;
        await using var command = CreateCommand(connection, transaction);
        await command.ExecuteNonQueryAsync(cancellationToken);
        MarkApplied(connection, version);
    }

    private void MarkApplied(DbConnection connection, int version)
    {
        _appliedConnection = connection;
        _appliedVersion = version;
    }

    // Created directly on the ADO.NET connection, so it is not itself intercepted.
    private DbCommand CreateCommand(DbConnection connection, DbTransaction? transaction)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = Sql;
        AddParameter(command, "user_id", context.UserId);
        AddParameter(command, "organization_id", context.OrganizationId);
        return command;
    }

    private static void AddParameter(DbCommand command, string name, Guid? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value?.ToString() ?? "";
        command.Parameters.Add(parameter);
    }
}
