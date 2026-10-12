using System;
using System.Net;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace K9.Api.Data.Migrations
{
    /// <summary>
    /// Security audit log: append-only for everyone below the table owner, readable by the
    /// runtime role only within the request's organization, and writable only through
    /// k9_record_audit_event.
    /// </summary>
    public partial class SecurityAudit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_events",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityAlwaysColumn),
                    occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "clock_timestamp()"),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: true),
                    actor_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    action = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    outcome = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    resource_type = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    resource_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    correlation_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    source_ip = table.Column<IPAddress>(type: "inet", nullable: true),
                    details = table.Column<string>(type: "jsonb", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_events", x => x.id);
                    table.CheckConstraint("ck_audit_events_action", "action ~ '^[a-z][a-z_]*(\\.[a-z][a-z_]*)+$'");
                    table.CheckConstraint("ck_audit_events_details", "details IS NULL OR jsonb_typeof(details) = 'object'");
                    table.CheckConstraint("ck_audit_events_outcome", "outcome IN ('success', 'denied', 'failure')");
                });

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_organization_id_id",
                table: "audit_events",
                columns: new[] { "organization_id", "id" },
                descending: new[] { false, true });

            migrationBuilder.Sql("""
                -- The runtime role can only read its organization's events. Writes go through
                -- k9_record_audit_event, and nobody below the table owner can change history.
                REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit_events FROM k9_app;

                ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
                CREATE POLICY audit_events_select ON audit_events FOR SELECT
                    USING (organization_id = k9_current_organization_id());

                -- Also stops the owner (migrations, maintenance) from editing history by accident.
                -- Retention has to be a deliberate migration that drops these triggers.
                CREATE FUNCTION public.k9_audit_events_append_only() RETURNS trigger
                    LANGUAGE plpgsql
                    SET search_path = ''
                    AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = 'insufficient_privilege';
                END
                $$;
                CREATE TRIGGER audit_events_no_update_or_delete BEFORE UPDATE OR DELETE ON public.audit_events
                    FOR EACH ROW EXECUTE FUNCTION public.k9_audit_events_append_only();
                CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON public.audit_events
                    FOR EACH STATEMENT EXECUTE FUNCTION public.k9_audit_events_append_only();

                -- The only write path. The actor and the request's organization come from the
                -- session settings the API derives from verified identity, never from
                -- parameters, and the timestamp from the database clock.
                CREATE FUNCTION public.k9_record_audit_event(
                    p_action text, p_outcome text, p_organization_id uuid, p_resource_type text,
                    p_resource_id text, p_correlation_id text, p_source_ip inet, p_details jsonb) RETURNS bigint
                    LANGUAGE plpgsql SECURITY DEFINER
                    SET search_path = ''
                    AS $$
                DECLARE
                    v_actor uuid := public.k9_current_user_id();
                    v_organization uuid := public.k9_current_organization_id();
                    v_id bigint;
                BEGIN
                    IF p_action IS NULL OR length(p_action) > 64 OR p_action !~ '^[a-z][a-z_]*(\.[a-z][a-z_]*)+$' THEN
                        RAISE EXCEPTION 'invalid audit action' USING ERRCODE = 'invalid_parameter_value';
                    END IF;
                    IF p_outcome IS NULL OR p_outcome NOT IN ('success', 'denied', 'failure') THEN
                        RAISE EXCEPTION 'invalid audit outcome' USING ERRCODE = 'invalid_parameter_value';
                    END IF;
                    IF p_resource_type IS NOT NULL AND (length(p_resource_type) > 64 OR p_resource_type !~ '^[a-z][a-z_]*$') THEN
                        RAISE EXCEPTION 'invalid audit resource type' USING ERRCODE = 'invalid_parameter_value';
                    END IF;
                    IF p_resource_id IS NOT NULL AND (length(p_resource_id) > 128 OR p_resource_id ~ '[[:cntrl:]]') THEN
                        RAISE EXCEPTION 'invalid audit resource id' USING ERRCODE = 'invalid_parameter_value';
                    END IF;
                    IF p_correlation_id IS NULL OR p_correlation_id !~ '^[A-Za-z0-9-]{1,64}$' THEN
                        RAISE EXCEPTION 'invalid correlation id' USING ERRCODE = 'invalid_parameter_value';
                    END IF;
                    IF p_details IS NOT NULL AND (jsonb_typeof(p_details) <> 'object' OR octet_length(p_details::text) > 4096) THEN
                        RAISE EXCEPTION 'invalid audit details' USING ERRCODE = 'invalid_parameter_value';
                    END IF;

                    -- An event may belong only to the organization this request entered. A denial
                    -- may also name one the actor belongs to (refused a higher-privilege action).
                    IF p_organization_id IS NOT NULL AND p_organization_id IS DISTINCT FROM v_organization THEN
                        IF p_outcome <> 'denied' OR v_actor IS NULL OR NOT EXISTS (
                            SELECT 1 FROM public.memberships m
                            WHERE m.organization_id = p_organization_id AND m.user_id = v_actor) THEN
                            RAISE EXCEPTION 'organization is not verified for this request' USING ERRCODE = 'insufficient_privilege';
                        END IF;
                    END IF;

                    INSERT INTO public.audit_events (organization_id, actor_user_id, action, outcome, resource_type,
                                                     resource_id, correlation_id, source_ip, details)
                    VALUES (p_organization_id, v_actor, p_action, p_outcome, p_resource_type,
                            p_resource_id, p_correlation_id, p_source_ip, p_details)
                    RETURNING id INTO v_id;
                    RETURN v_id;
                END
                $$;

                REVOKE ALL ON FUNCTION public.k9_record_audit_event(text, text, uuid, text, text, text, inet, jsonb) FROM PUBLIC;
                GRANT EXECUTE ON FUNCTION public.k9_record_audit_event(text, text, uuid, text, text, text, inet, jsonb) TO k9_app;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP FUNCTION public.k9_record_audit_event(text, text, uuid, text, text, text, inet, jsonb);");

            migrationBuilder.DropTable(
                name: "audit_events");

            migrationBuilder.Sql("DROP FUNCTION public.k9_audit_events_append_only();");
        }
    }
}
