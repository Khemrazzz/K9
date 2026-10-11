#!/bin/sh
# Runs once, when the postgres-data volume is first initialised.
#
# k9_owner owns the k9 schema and runs migrations.
# k9_app is the runtime role: DML only, and it can never bypass row-level
# security (it is not a table owner, superuser or BYPASSRLS role).
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v k9_owner_pw="$K9_OWNER_PASSWORD" \
  -v k9_app_pw="$K9_APP_PASSWORD" \
  -v keycloak_pw="$KEYCLOAK_DB_PASSWORD" <<'SQL'
CREATE ROLE k9_owner LOGIN PASSWORD :'k9_owner_pw';
CREATE ROLE k9_app LOGIN PASSWORD :'k9_app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE keycloak LOGIN PASSWORD :'keycloak_pw';

CREATE DATABASE k9 OWNER k9_owner;
CREATE DATABASE keycloak OWNER keycloak;

REVOKE ALL ON DATABASE k9 FROM PUBLIC;
GRANT CONNECT ON DATABASE k9 TO k9_app;
REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname k9 <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO k9_app;

-- Tables and sequences created later by k9_owner's migrations are usable by k9_app.
ALTER DEFAULT PRIVILEGES FOR ROLE k9_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO k9_app;
ALTER DEFAULT PRIVILEGES FOR ROLE k9_owner IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO k9_app;
SQL
