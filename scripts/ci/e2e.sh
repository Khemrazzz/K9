#!/usr/bin/env bash
# CI stage "e2e": a disposable stack (Postgres, Keycloak, migrations, API) under its own
# compose project with throwaway credentials, the web app's production build, and the
# Playwright suite through the real Keycloak login. Everything is torn down afterwards,
# including volumes, whether the run passes or fails.
# Needs Docker, Node 22, openssl and free ports 3000, 5080, 5432 and 8081.
# Locally, K9_E2E_SKIP_INSTALL=1 reuses apps/web/node_modules instead of running npm ci, and
# K9_E2E_KEEP_STACK=1 leaves the stack (and its env file) running for debugging.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
project="${K9_E2E_PROJECT:-k9-e2e}"
# Absolute paths: the cleanup trap runs after the script has changed directory.
work="$root/artifacts/e2e"
rm -rf "$work"
mkdir -p "$work"
export CI="${CI:-true}"

for port in 3000 5080 5432 8081; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "Port $port is in use. Stop the local stack first (docker compose --profile api stop) and any 'next' server." >&2
    echo "Restart it afterwards with: docker compose --profile api up -d --wait" >&2
    exit 1
  fi
done

# Throwaway credentials for this run only, masked in GitHub Actions logs. The mask is
# printed from this shell, never from inside $(...), so it cannot leak into a value.
# Strip CR too: Windows builds of openssl end lines with CRLF, and a stray \r makes the
# client secret the web app sends differ from the one Keycloak imported.
random() { openssl rand "-${1:-hex}" "${2:-24}" | tr -d '\r\n'; }
mask() { if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::add-mask::$1"; fi; }
postgres_password="$(random)" && mask "$postgres_password"
owner_password="$(random)" && mask "$owner_password"
app_password="$(random)" && mask "$app_password"
keycloak_db_password="$(random)" && mask "$keycloak_db_password"
keycloak_admin_password="$(random)" && mask "$keycloak_admin_password"
web_client_secret="$(random)" && mask "$web_client_secret"
dev_user_password="$(random)" && mask "$dev_user_password"
session_secret="$(random base64 48)" && mask "$session_secret"
env_file="$work/stack.env"
cat > "$env_file" <<EOF
POSTGRES_SUPERUSER_PASSWORD=$postgres_password
K9_OWNER_PASSWORD=$owner_password
K9_APP_PASSWORD=$app_password
KEYCLOAK_DB_PASSWORD=$keycloak_db_password
KEYCLOAK_ADMIN_PASSWORD=$keycloak_admin_password
K9_WEB_CLIENT_SECRET=$web_client_secret
K9_DEV_USER_PASSWORD=$dev_user_password
EOF

# Docker on Windows (Git Bash) needs a Windows path for the env file.
host_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
compose() { docker compose -p "$project" --env-file "$(host_path "$env_file")" --profile api "$@"; }
cleanup() {
  local status=$?
  cd "$root"
  if [ "$status" -ne 0 ]; then
    compose logs --no-color > "$work/compose.log" 2>&1 || echo "Could not collect container logs." >&2
  fi
  if [ "${K9_E2E_KEEP_STACK:-}" = "1" ]; then
    echo "K9_E2E_KEEP_STACK=1: leaving project $project running for debugging. Remove it with:" >&2
    echo "  docker compose -p $project --env-file $env_file --profile api down -v && rm $env_file" >&2
    exit "$status"
  fi
  # A failed teardown fails the run: leftover containers or volumes must never go unnoticed.
  if ! compose down --volumes --remove-orphans > "$work/teardown.log" 2>&1; then
    echo "::error::Teardown of compose project $project failed; see $work/teardown.log." >&2
    status=1
  fi
  local leftover
  leftover="$(docker ps -aq --filter "label=com.docker.compose.project=$project" | wc -l)"
  leftover=$((leftover + $(docker volume ls -q --filter "label=com.docker.compose.project=$project" | wc -l)))
  if [ "$leftover" -ne 0 ]; then
    echo "::error::$leftover container(s) or volume(s) of $project remain after teardown." >&2
    status=1
  fi
  rm -f "$env_file"
  exit "$status"
}
trap cleanup EXIT

echo "::group::Start disposable stack (fresh database, migrations, Keycloak realm import)"
compose up -d --build --wait --wait-timeout 300
echo "::endgroup::"

# The web app reads configuration from the process environment; nothing is written to apps/web.
export K9_APP_URL=http://localhost:3000
export K9_API_URL=http://localhost:5080
export K9_OIDC_ISSUER=http://localhost:8081/realms/k9
export K9_OIDC_CLIENT_ID=k9-web
export K9_OIDC_CLIENT_SECRET="$web_client_secret"
export K9_OIDC_ALLOW_HTTP=true
export K9_SESSION_SECRET="$session_secret"
export K9_DEV_USER_PASSWORD="$dev_user_password"

cd apps/web
echo "::group::Install, browser and production build"
if [ "${K9_E2E_SKIP_INSTALL:-}" != "1" ]; then npm ci --no-audit --no-fund; fi
if [ "$(uname -s)" = "Linux" ]; then npx playwright install --with-deps chromium; else npx playwright install chromium; fi
npm run build
echo "::endgroup::"

echo "::group::Playwright"
npx playwright test
echo "::endgroup::"

node ../../scripts/ci/verify-test-results.mjs e2e playwright-report/e2e-results.json
