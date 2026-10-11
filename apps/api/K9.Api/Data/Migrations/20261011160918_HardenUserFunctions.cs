using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace K9.Api.Data.Migrations
{
    /// <summary>
    /// Hardens the SECURITY DEFINER functions, which run with the table owner's rights:
    /// an empty search_path with every object schema-qualified (so no caller-controlled
    /// schema can shadow a table or function), and validation of every input.
    /// CREATE OR REPLACE keeps the existing owner and EXECUTE grants (k9_app only).
    /// </summary>
    public partial class HardenUserFunctions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION public.k9_upsert_user(p_subject text, p_email text, p_display_name text) RETURNS uuid
                    LANGUAGE plpgsql SECURITY DEFINER
                    SET search_path = ''
                    AS $$
                DECLARE
                    v_id uuid;
                    v_email text;
                    v_display_name text;
                BEGIN
                    -- The subject is the identity. Reject rather than reinterpret anything odd.
                    IF p_subject IS NULL OR p_subject = '' OR length(p_subject) > 255 OR p_subject ~ '[[:cntrl:][:space:]]' THEN
                        RAISE EXCEPTION 'invalid subject' USING ERRCODE = 'invalid_parameter_value';
                    END IF;

                    -- Profile fields are informational: keep them if well-formed, otherwise drop or trim.
                    v_email := lower(btrim(p_email));
                    IF v_email IS NULL OR length(v_email) > 320 OR v_email !~ '^[^@[:space:][:cntrl:]]+@[^@[:space:][:cntrl:]]+$' THEN
                        v_email := NULL;
                    END IF;
                    v_display_name := NULLIF(left(btrim(regexp_replace(p_display_name, '[[:cntrl:]]', '', 'g')), 200), '');

                    INSERT INTO public.users (id, subject, email, display_name, created_at)
                    VALUES (gen_random_uuid(), p_subject, v_email, v_display_name, now())
                    ON CONFLICT (subject) DO UPDATE
                        SET email = EXCLUDED.email, display_name = EXCLUDED.display_name
                        WHERE public.users.email IS DISTINCT FROM EXCLUDED.email
                           OR public.users.display_name IS DISTINCT FROM EXCLUDED.display_name
                    RETURNING id INTO v_id;

                    IF v_id IS NULL THEN
                        SELECT u.id INTO v_id FROM public.users u WHERE u.subject = p_subject;
                    END IF;
                    RETURN v_id;
                END
                $$;

                CREATE OR REPLACE FUNCTION public.k9_find_user_id_by_email(p_email text) RETURNS uuid
                    LANGUAGE sql STABLE SECURITY DEFINER
                    SET search_path = ''
                    AS $$
                    SELECT CASE WHEN count(*) = 1 THEN (array_agg(u.id))[1] END
                    FROM public.users u
                    WHERE length(p_email) <= 320 AND u.email = lower(btrim(p_email))
                $$;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION public.k9_upsert_user(p_subject text, p_email text, p_display_name text) RETURNS uuid
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

                CREATE OR REPLACE FUNCTION public.k9_find_user_id_by_email(p_email text) RETURNS uuid
                    LANGUAGE sql STABLE SECURITY DEFINER
                    SET search_path = public, pg_temp
                    AS $$
                    SELECT CASE WHEN count(*) = 1 THEN (array_agg(id))[1] END
                    FROM users WHERE lower(email) = lower(p_email)
                $$;
                """);
        }
    }
}
