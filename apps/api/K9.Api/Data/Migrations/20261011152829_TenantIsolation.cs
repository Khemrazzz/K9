using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace K9.Api.Data.Migrations
{
    /// <summary>
    /// Row-level security for tenant isolation.
    ///
    /// The API connects as <c>k9_app</c>, which does not own these tables, so the policies
    /// always apply to it. The request's user and organization arrive as session settings
    /// (see TenantContextInterceptor). The invariant: every row the API reads or writes
    /// belongs to the request's organization, apart from the caller's own user and
    /// membership rows, which <c>/api/me</c> needs to list their organizations.
    ///
    /// Tables are not FORCE'd, so the owner (<c>k9_owner</c>, which also owns the
    /// SECURITY DEFINER functions below) bypasses the policies by design.
    /// </summary>
    public partial class TenantIsolation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                CREATE FUNCTION k9_current_user_id() RETURNS uuid
                    LANGUAGE sql STABLE
                    AS $$ SELECT NULLIF(current_setting('k9.user_id', true), '')::uuid $$;

                CREATE FUNCTION k9_current_organization_id() RETURNS uuid
                    LANGUAGE sql STABLE
                    AS $$ SELECT NULLIF(current_setting('k9.organization_id', true), '')::uuid $$;

                ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
                ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
                ALTER TABLE users ENABLE ROW LEVEL SECURITY;

                -- Organizations: the active one, plus any the caller belongs to (for /api/me).
                -- No DELETE policy: the API cannot delete organizations yet.
                CREATE POLICY organizations_select ON organizations FOR SELECT
                    USING (id = k9_current_organization_id()
                        OR id IN (SELECT organization_id FROM memberships WHERE user_id = k9_current_user_id()));
                CREATE POLICY organizations_insert ON organizations FOR INSERT
                    WITH CHECK (id = k9_current_organization_id());
                CREATE POLICY organizations_update ON organizations FOR UPDATE
                    USING (id = k9_current_organization_id())
                    WITH CHECK (id = k9_current_organization_id());

                -- Memberships: all of the active organization's, plus the caller's own.
                -- Writes are confined to the active organization.
                CREATE POLICY memberships_select ON memberships FOR SELECT
                    USING (organization_id = k9_current_organization_id() OR user_id = k9_current_user_id());
                CREATE POLICY memberships_insert ON memberships FOR INSERT
                    WITH CHECK (organization_id = k9_current_organization_id());
                CREATE POLICY memberships_update ON memberships FOR UPDATE
                    USING (organization_id = k9_current_organization_id())
                    WITH CHECK (organization_id = k9_current_organization_id());
                CREATE POLICY memberships_delete ON memberships FOR DELETE
                    USING (organization_id = k9_current_organization_id());

                -- Users: the caller, plus members of the active organization. Read-only for
                -- the API; rows are written by k9_upsert_user only.
                CREATE POLICY users_select ON users FOR SELECT
                    USING (id = k9_current_user_id()
                        OR id IN (SELECT user_id FROM memberships WHERE organization_id = k9_current_organization_id()));
                REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON users FROM k9_app;

                -- Maps an identity-provider subject to a K9 user, creating it on first sign-in.
                CREATE FUNCTION k9_upsert_user(p_subject text, p_email text, p_display_name text) RETURNS uuid
                    LANGUAGE plpgsql SECURITY DEFINER
                    SET search_path = public, pg_temp
                    AS $$
                DECLARE
                    v_id uuid;
                BEGIN
                    INSERT INTO users (id, subject, email, display_name, created_at)
                    VALUES (gen_random_uuid(), p_subject, p_email, p_display_name, now())
                    ON CONFLICT (subject) DO UPDATE
                        SET email = EXCLUDED.email, display_name = EXCLUDED.display_name
                        WHERE users.email IS DISTINCT FROM EXCLUDED.email
                           OR users.display_name IS DISTINCT FROM EXCLUDED.display_name
                    RETURNING id INTO v_id;

                    IF v_id IS NULL THEN
                        SELECT id INTO v_id FROM users WHERE subject = p_subject;
                    END IF;
                    RETURN v_id;
                END
                $$;

                -- Resolves an email for "add member". Returns NULL unless exactly one user matches.
                CREATE FUNCTION k9_find_user_id_by_email(p_email text) RETURNS uuid
                    LANGUAGE sql STABLE SECURITY DEFINER
                    SET search_path = public, pg_temp
                    AS $$
                    SELECT CASE WHEN count(*) = 1 THEN (array_agg(id))[1] END
                    FROM users WHERE lower(email) = lower(p_email)
                $$;

                REVOKE ALL ON FUNCTION k9_upsert_user(text, text, text) FROM PUBLIC;
                REVOKE ALL ON FUNCTION k9_find_user_id_by_email(text) FROM PUBLIC;
                GRANT EXECUTE ON FUNCTION k9_upsert_user(text, text, text) TO k9_app;
                GRANT EXECUTE ON FUNCTION k9_find_user_id_by_email(text) TO k9_app;

                -- The runtime role has no business with migration history.
                REVOKE ALL ON "__EFMigrationsHistory" FROM k9_app;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DROP FUNCTION k9_find_user_id_by_email(text);
                DROP FUNCTION k9_upsert_user(text, text, text);

                DROP POLICY users_select ON users;
                DROP POLICY memberships_delete ON memberships;
                DROP POLICY memberships_update ON memberships;
                DROP POLICY memberships_insert ON memberships;
                DROP POLICY memberships_select ON memberships;
                DROP POLICY organizations_update ON organizations;
                DROP POLICY organizations_insert ON organizations;
                DROP POLICY organizations_select ON organizations;

                ALTER TABLE users DISABLE ROW LEVEL SECURITY;
                ALTER TABLE memberships DISABLE ROW LEVEL SECURITY;
                ALTER TABLE organizations DISABLE ROW LEVEL SECURITY;

                DROP FUNCTION k9_current_organization_id();
                DROP FUNCTION k9_current_user_id();
                """);
        }
    }
}
