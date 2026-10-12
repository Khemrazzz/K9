# K9
Your Cyber Hacker... V1 <under dev>
Linux Pro Master ...V2  <Under research>
AI Powered Hacker...V3  <incoming>

## Local infrastructure (V2 foundation)

K9 V2 runs its supporting services with Docker Compose:

| Service    | URL / port                  | Purpose                                   |
|------------|-----------------------------|-------------------------------------------|
| PostgreSQL | `127.0.0.1:5432`            | `k9` application database and Keycloak's database |
| Keycloak   | http://localhost:8081       | OIDC identity provider, realm `k9`        |

Both ports bind to localhost only. Override them with `K9_POSTGRES_PORT` and
`K9_KEYCLOAK_PORT` in `.env`.

### First start

```bash
cp .env.example .env      # then replace every "change-me" value
docker compose up -d --wait
```

`.env` is git-ignored. On the first start, Postgres creates the database roles and
Keycloak imports the realm from `infrastructure/keycloak/k9-realm.dev.json`. Both
steps only run once. To apply changes to the passwords or the realm file, wipe
the data and start again with `docker compose down -v`.

### What gets created

**Postgres** (`infrastructure/postgres/init/01-databases.sh`)

- `k9_owner` owns the `k9` database and runs migrations.
- `k9_app` is the role the API runs as. It can read and write table rows, but it
  can't change the schema or bypass row-level security. Tenant isolation will rely
  on this.
- `keycloak` owns the `keycloak` database. `k9_app` can't connect to it.

**Keycloak realm `k9`**

- `k9-web` is the client for the Next.js console. It uses the authorization code
  flow with PKCE (S256), which is required. The password grant is disabled.
  Redirects are only allowed to `http://localhost:3000/*`.
- `k9-api` is the API's audience. Access tokens issued to `k9-web` carry
  `aud: k9-api`, last 5 minutes, and have the issuer `http://localhost:8081/realms/k9`.
- Refresh tokens are rotated and can't be reused. Brute-force protection is on.
- There are two dev users: `alice@acme.test` and `bob@globex.test`. Their password
  is `K9_DEV_USER_PASSWORD`. They'll be placed in separate organizations to test
  tenant isolation.

The Keycloak admin console is at http://localhost:8081/admin. Sign in as `admin`
with `KEYCLOAK_ADMIN_PASSWORD`.

> The realm file is for development only. It contains test users and
> `http://localhost` redirect URIs. Don't import it into a shared or production
> Keycloak.

## API (ASP.NET Core 10)

The API is in `apps/api`. You need the .NET 10 SDK and the infrastructure above running.

### Run it on your machine

Store the connection strings in .NET user-secrets. They stay outside the repository.
Use the passwords from your `.env`:

```bash
cd apps/api
dotnet user-secrets --project K9.Api set "ConnectionStrings:K9" "Host=localhost;Port=5432;Database=k9;Username=k9_app;Password=<K9_APP_PASSWORD>"
dotnet user-secrets --project K9.Api set "ConnectionStrings:K9Migrations" "Host=localhost;Port=5432;Database=k9;Username=k9_owner;Password=<K9_OWNER_PASSWORD>"

dotnet run --project K9.Api -- migrate   # applies migrations as k9_owner
dotnet run --project K9.Api              # serves http://localhost:5080
```

### Tests

```bash
cd apps/api
dotnet test
```

The tests need Docker running. They start their own Postgres container, built with
the same init script as above, and don't touch your dev database. Requests go through
the real authentication and authorization pipeline. The only test-specific piece is
the signing key: tests sign their own tokens instead of fetching Keycloak's keys.

### Run it in Docker

```bash
docker compose --profile api up -d --build
```

This runs migrations once, then starts the API on http://localhost:5080. Inside the
container, the API fetches Keycloak's discovery document and signing keys from
`http://keycloak:8080`. It still requires tokens to carry the public issuer
`http://localhost:8081/realms/k9`, which is what the browser sees. Keycloak's
`KC_HOSTNAME_BACKCHANNEL_DYNAMIC` setting makes both work.

### Endpoints

| Method | Path | Access |
|---|---|---|
| GET | `/health/live`, `/health/ready` | Anonymous. `ready` checks the database. |
| GET | `/api/me` | Any signed-in user. Creates the K9 user on first call. |
| POST | `/api/organizations` | Any signed-in user. The creator becomes `Owner`. |
| GET | `/api/organizations/{id}` | Members (`Viewer` and up) |
| GET | `/api/organizations/{id}/members` | Members (`Viewer` and up) |
| POST | `/api/organizations/{id}/members` | `Admin` and up. Can't grant a role higher than their own. |
| PATCH | `/api/organizations/{id}/members/{userId}` | `Admin` and up. Can't set, or change, a role above their own. The last owner can't be demoted. |
| DELETE | `/api/organizations/{id}/members/{userId}` | `Admin` and up, or any member removing themselves. The last owner can't be removed. |
| GET | `/api/organizations/{id}/audit-events` | `Admin` and up. See [Security audit log](#security-audit-log). |

### How access is enforced

1. **Authentication.** Every endpoint requires a valid Keycloak access token unless it
   explicitly allows anonymous access. The API checks the issuer, the audience
   (`k9-api`), the expiry and the RS256 signature. It rejects refresh and ID tokens
   (`typ` must be `Bearer`) and tokens without a `sub` claim.
2. **Authorization.** The organization ID in the URL is only a request. For each call,
   the API looks up the caller's membership in that organization in the database and
   checks their role. Nothing the client sends is trusted on its own.
3. **Row-level security.** The verified user and organization are passed into each
   database connection as session settings. Postgres policies then hide or reject any
   row outside that organization. This holds even if an endpoint forgets a filter.
   The `k9_app` role can't turn the policies off, change the schema, or write the
   `users` table directly. Users are created only through a vetted database function.

The policies are in `K9.Api/Data/Migrations/*_TenantIsolation.cs`.
`TenantIsolationTests` checks each layer separately, including direct database
queries with no application filters.

Session settings are written whenever a connection opens, and again before any query
if the request context has changed since. Npgsql clears them when a connection goes
back to the pool. `ConnectionPoolingTests` proves both, including concurrent requests
from two tenants on a 4-connection pool, mixed with error responses.

These are session-level settings, not `SET LOCAL`, because EF runs most queries outside
an explicit transaction. Postgres still reverts them when a transaction, or a savepoint,
rolls back. So the interceptor tracks which transaction it wrote them in, and rewrites
them on the next command after that transaction ends or a savepoint is rolled back.
`TransactionContextTests` covers rollback, disposal without commit, a failed statement,
a savepoint rollback and raw SQL.

The one path not covered is raw ADO.NET commands created on EF's connection. They
bypass EF's interceptors and see whatever was last applied. All database access must
go through EF (`SqlQuery`/`ExecuteSql` included), and code must never call `set_config`
on these settings itself.

The two `SECURITY DEFINER` functions run with the table owner's rights, so they're
locked down. Their `search_path` is empty and every object is schema-qualified. Only
`k9_app` can execute them. They reject malformed subjects and clean the profile fields.
`k9_app` can't create the temp tables, functions or schemas that could shadow
objects they use. `SecurityHardeningTests` covers this, plus hostile token claims,
route values and request bodies.

#### What row-level security does *not* protect against

RLS is defense in depth. It doesn't replace the controls above it. The session
settings are written by the application, and `k9_app` is allowed to write them. Anyone
who can run arbitrary SQL as `k9_app` can therefore claim to be any user or
organization: for example, through a SQL injection bug or a leaked `k9_app` password.
The protections against that are:

- **No string-built SQL.** All queries go through EF Core with parameters. The only
  hand-written command is a fixed, parameterized `set_config`. The build treats EF's
  SQL-injection analyzer warning (EF1002) as an error.
- **A narrow database role.** `k9_app` can't change the schema, turn off RLS, write
  `users`, read migration history or touch Keycloak's database. A leaked password is
  bounded by that, but it is still a full breach of tenant data.
- **Membership checks in the API.** These are independent of RLS, and both layers are
  tested separately.
- **Secrets stay out of the repo.** Connection strings live in user-secrets or the
  environment, and should move to a secrets manager in deployed environments.

### Security audit log

Security-relevant actions are recorded in the `audit_events` table. Each event says who
acted, in which organization, on what, when, and with what outcome.

| Action | Recorded when |
|---|---|
| `auth.token_rejected` | A presented token is refused (expired, wrong audience/issuer, bad signature, refresh/ID token, malformed). Only the reason category is stored. Nothing from the token is kept, not even its subject. |
| `authz.organization_access` | A user is denied an organization-scoped endpoint. Stored with the required and held role. |
| `organization.create` | An organization is created. |
| `membership.add` / `.change_role` / `.remove` | Members are added, re-roled or removed, with the role before and after. Refusals (role above own, last owner, unknown user) are recorded too. |
| `audit.read` | Someone reads the audit log. |

Sign-in, failed passwords, sign-out, refresh and refresh-token reuse happen at Keycloak.
They're in Keycloak's event store, which the dev realm enables with 90-day retention.
Bringing them into K9's log is future work.

**Who an event belongs to.** The database decides. Rows are written only by the
`k9_record_audit_event` function, which takes the actor and organization from the
request's verified session context, never from parameters. The timestamp comes from the
database clock. An event can be filed under:

- the organization the request entered after its membership check, or
- for a denial, an organization the actor belongs to.

An outsider's denied attempt is kept platform-side, with the organization as its target
but not its owner, so outsiders can't write into a tenant's log. Correlation IDs are
generated by the server and returned as `X-Correlation-Id`. Client-supplied correlation
and trace headers are ignored.

**Integrity.** `k9_app` can't insert into, update, delete or truncate `audit_events`; it
can only call the function. Triggers also block `UPDATE`, `DELETE` and `TRUNCATE` for the
table owner, so retention has to be a deliberate migration. Reads go through RLS
(`organization_id` = the request's organization) and require `Admin`. Details are a
small, allow-listed JSON object built by the API. Request bodies, emails of non-users,
tokens, passwords and secrets are never recorded.

**When the audit log is unavailable:**

| Operation | Behavior |
|---|---|
| Creating organizations, adding, changing or removing members | Fails closed. The change and its audit record share one transaction; without the record, nothing changes and the API returns 503. |
| Reading the audit log | Fails closed (503). |
| Refusals (bad tokens, denied access, rule violations) | Still refused. The missed record is written to the error log with the correlation ID. |
| Plain reads (`/api/me`, organization, members) | Not audited, so they keep working. |

**Reading it.** `GET /api/organizations/{id}/audit-events` returns events newest first.
Optional filters: `action`, `outcome`, `actorUserId`, `from`, `to`. For more pages,
pass `limit` (1–200) and set `before` to the previous page's `nextCursor`. Paging is
keyset-based, so new events never shift later pages.

`AuditTests` covers recording, the identity rules, cross-tenant isolation, pagination,
malformed queries, append-only storage, spoofed and malformed writes, missing token
material, and fail-closed behavior. `MembershipManagementTests` covers the role
ceilings, the last-owner rule, and the concurrent-demotion race. Membership changes
lock the organization row, so concurrent demotions can't remove the last owner.

**Migration.** `SecurityAudit` adds the table, policies, triggers and function. Run
`dotnet run --project K9.Api -- migrate` (or recreate the `api` compose profile). An
existing Keycloak keeps its realm, so turn on its event settings in the admin console
(Realm settings → Events) or with `kcadm.sh`. A fresh realm import includes them.

## Web console (Next.js 16)

The console is in `apps/web`. It needs Node 22+, the infrastructure above, and the API
running on http://localhost:5080, either with `dotnet run` or with the `api` compose profile.

```bash
cd apps/web
npm ci
cp .env.example .env.local   # set K9_OIDC_CLIENT_SECRET (= K9_WEB_CLIENT_SECRET) and K9_SESSION_SECRET
npm run dev                  # http://localhost:3000
```

Sign in as `alice@acme.test` or `bob@globex.test` with `K9_DEV_USER_PASSWORD`.

### How sessions work

- **Server-side login.** The Next.js server is a confidential OIDC client. It signs users
  in with the authorization code flow, using PKCE, `state` and `nonce`
  (`openid-client`). The client secret never leaves the server.
- **Tokens never reach browser JavaScript.** Keycloak's tokens are encrypted (JWE,
  A256GCM) into HttpOnly, `SameSite=Lax` cookies. Over HTTPS the cookies are also
  `Secure` and use the `__Host-` prefix. The access and refresh tokens share one cookie.
  The ID token gets its own cookie, because it's only needed for logout and together
  they would exceed the 4 KB cookie limit.
- **Refresh.** `src/proxy.ts` refreshes the access token within 60 seconds of expiry.
  Concurrent refreshes of the same token share one request, because Keycloak rotates
  refresh tokens and rejects reuse. If Keycloak rejects the refresh, the session is
  cleared and the user signs in again.
- **Sign-out** is a POST only, and it checks the request's origin. It revokes the
  refresh token, clears the cookies, then ends the Keycloak SSO session.
- **Known limitation; must be fixed before the first customer deployment.** The session
  lives entirely in the cookie, so the server can't revoke it on its own. A copy of the
  cookie stolen before sign-out still holds a valid access token for up to 5 minutes;
  after that, the refresh fails because the refresh token was revoked. Refresh
  deduplication is also per process. The fix: a server-side session store holding an
  opaque session ID, shared by every web instance and deleted on sign-out, as OWASP's
  session-management guidance recommends.
- **Authorization.** The console never decides who can see an organization. Every page
  calls the API with the user's token and renders the API's answer: data, "No access"
  (403), or "temporarily unavailable". The organization switcher lists only what
  `/api/me` returns. The remembered organization is a preference, not a permission.
- **Request hardening:**
  - Each request gets a nonce-based CSP.
  - Pages can't be framed, and `nosniff` is set.
  - `Cache-Control: no-store` applies under `/app` and `/auth`.
  - `returnTo` only accepts paths under `/app`.
  - Server Actions rely on Next.js's built-in origin check.
  - `cacheComponents` is off, so no tenant data is cached on the server.

### Checks and tests

```bash
cd apps/web
npm run check      # typecheck (strict), ESLint (no warnings), unit tests, production build
npm run test:e2e   # Playwright against the real stack
```

Before running the end-to-end tests:

- Have `docker compose --profile api up -d` running.
- Run `npm run build`.
- Install the browser once with `npx playwright install chromium`.

The tests take `K9_DEV_USER_PASSWORD` and `K9_SESSION_SECRET` from the environment.
If either isn't set, they fall back to the root `.env` and `apps/web/.env.local`. They
sign in through the real Keycloak and cover:

- the Acme/Globex tenant boundary
- role-aware UI
- organization switching
- deep links and open-redirect attempts
- tampered, expiring and rejected sessions
- sign-out, including replaying the old cookie afterwards
- cross-site sign-out attempts, response headers, and tokens staying out of the page

`npm audit --omit=dev` reports no vulnerabilities. A full `npm audit` reports a `braces`
advisory inside ESLint's tooling. No patched version exists, and it doesn't ship to users.
It's a documented exception; see [Dependency exceptions](#dependency-exceptions).

## CI

`.github/workflows/ci.yml` runs on every pull request, and on pushes to `master` and
`v2-foundation`. Each job runs one script from `scripts/ci/`, so you can reproduce any
stage locally with the same command.

| Job | Script | What it proves |
|---|---|---|
| `backend` | `scripts/ci/backend.sh` | Locked NuGet restore. Release build with warnings and vulnerable packages as errors. All API tests against real Postgres (Testcontainers). Then the security regression gate. |
| `web` | `scripts/ci/web.sh` | `npm ci` from the lockfile, strict typecheck, ESLint with zero warnings, unit tests, and the production build (no secrets needed). |
| `security` | `scripts/ci/security.sh` | gitleaks over the full git history and over every file in the change. NuGet vulnerability check, including transitive packages. `npm audit` of production dependencies (no exceptions), and of all dependencies against documented exceptions. |
| `e2e` | `scripts/ci/e2e.sh` | A disposable stack (fresh Postgres, migrations, Keycloak realm import, API container) under its own compose project with throwaway credentials. Then the web production build, the Playwright suite through the real Keycloak login, the security regression gate, and teardown of containers and volumes whether it passes or fails. Runs after `backend` and `web` pass. |
| `all-checks` | — | The single check to require in branch protection. Fails unless every job above succeeded, so a skipped or cancelled job can't count as green. |

### Running the stages locally

These need Git Bash or another bash, Docker, the .NET 10 SDK and Node 22. Run them from
the repository root:

```bash
bash scripts/ci/backend.sh    # about 4 min; needs Docker
bash scripts/ci/web.sh        # runs npm ci, which replaces apps/web/node_modules
bash scripts/ci/security.sh   # needs Docker; the history scan reads the whole repository
docker compose --profile api stop   # e2e needs ports 3000, 5080, 5432 and 8081
bash scripts/ci/e2e.sh        # own compose project and data; your dev stack and .env are untouched
docker compose --profile api up -d --wait   # not `start`: only `up` waits for Postgres before migrating
```

To re-run the end-to-end stage without reinstalling, use
`K9_E2E_SKIP_INSTALL=1 bash scripts/ci/e2e.sh`. That reuses `apps/web/node_modules`;
CI always runs `npm ci`. `K9_E2E_KEEP_STACK=1` leaves the disposable stack running after
the run so you can inspect it, and prints the command that removes it. Never set it in CI.

**Not yet verified on GitHub's runners.** Everything above was run locally on Windows
(Git Bash, Docker Desktop). These parts only GitHub can confirm:

- the workflow's first real run, including its timings
- `setup-dotnet` caching with the `apps/api/**/packages.lock.json` glob
- `playwright install --with-deps` on `ubuntu-24.04`
- Testcontainers' cleanup container on the runner
- that `all-checks` reports correctly when a job is skipped or cancelled

Check them on the first pull request after pushing.

Reports go to `artifacts/` (git-ignored): TRX test results, Playwright's JSON report,
scanner reports, and container logs if the end-to-end stage fails.

### Security regression gate

`scripts/ci/security-tests.json` lists the security guarantees every run must exercise:

- JWT rejection: expired, wrong issuer or audience, untrusted key, refresh or ID token
- cross-tenant denial, RLS reads and writes, pooled-connection and rollback isolation
- privilege ceilings and the last-owner rule, including the concurrent race
- append-only and unspoofable audit records, and fail-closed security changes
- rejected tokens audited without token material
- session tampering, refresh, sign-out, cross-site sign-out, and tokens kept out of the page

`scripts/ci/verify-test-results.mjs` reads the TRX or Playwright report and fails the job
if any listed test is missing (renamed, deleted or filtered out), skipped or failing, or
if the total drops below the recorded minimum (96 backend, 14 end-to-end). When you
add security tests, add them to the manifest and raise the minimum.

### Supply chain and secrets

- **Triggers.** The workflow runs on `pull_request`, never `pull_request_target`, so pull
  request code, including forks, gets a read-only token and no repository secrets.
- **No stored secrets.** No job uses repository secrets. The end-to-end stack creates
  random credentials per run, masks them in the log, keeps them in a temporary env file
  under `artifacts/` that is deleted at teardown, and never writes them into
  `apps/web`. Playwright traces, which record cookies, are off in CI. Failure artifacts
  are screenshots, the JSON report and container logs.
- **Least privilege.** The workflow grants nothing by default. Each job asks only for
  `contents: read`, and checkout doesn't persist the token.
- **Pinning:**
  - Actions are pinned to full commit SHAs, with the release in a comment.
  - The gitleaks image is pinned by digest.
  - The runner is `ubuntu-24.04`, with exact .NET SDK and Node versions.
  - NuGet (`packages.lock.json`, locked-mode restore) and npm (`package-lock.json`,
    `npm ci`) both resolve from committed lockfiles, and so does the API container build.
- **Updating a pin.** Resolve the new release's commit with
  `git ls-remote https://github.com/<owner>/<action> refs/tags/<tag>`, read its
  `action.yml` at that commit, then update the SHA and the comment.
- **Scanner failures fail the job.** A scanner that crashes, returns unreadable output
  or reports no projects fails the job; it never passes silently.

### Secret scanning

gitleaks runs over the full history and over every file a commit would include. The
second scan copies tracked and non-ignored files, so it never reads `node_modules`,
build output or your local `.env` files. `.gitleaksignore` suppresses only exact,
reviewed findings, by fingerprint.

Today those are all in the superseded Java prototype. Its first commit (July 2025) put an
HS256 JWT signing key in `application.properties`, and the old tests reused it. That key
is in the public history, so treat it as compromised: never use it, and rotate it
anywhere the prototype ran. Deleting `HackerPlatform-Backend` removes the working-tree
entries; removing the history entries needs a history rewrite.

### Dependency exceptions

`security/dependency-exceptions.json` documents advisories that can't be fixed yet,
with their impact, the reason, the condition for review and a `reviewBy` date. CI fails on:

- any advisory not listed
- a listed advisory that now affects a different package
- an exception whose `reviewBy` date has passed

Production npm dependencies and all NuGet packages have no exceptions at all.

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Port 5432 is in use` from `e2e.sh` | Your dev stack is running. Run `docker compose --profile api stop`, and stop any `next start`. Restart it afterwards with `up -d --wait`. |
| `e2e.sh` reports leftover containers or a failed teardown | The run fails on purpose. Remove them with `docker compose -p k9-e2e --env-file .env.example --profile api down -v`. |
| `Sign-in callback rejected` in an end-to-end log | The message names the cause. A JWT `iat`/`exp` complaint means clock skew between the host and Docker; on Docker Desktop, restarting Docker resyncs the VM clock. |
| `NU1004` / locked-mode restore fails | A package changed without updating `packages.lock.json`. Run `dotnet restore apps/api/K9.slnx --force-evaluate` and commit the lock files. |
| `NU190x` vulnerability errors in the build | NuGet audit found an advisory. Upgrade the package. Warnings are errors by design. |
| Security regression gate: "Missing security test" | A listed test was renamed or removed. Restore it, or update `scripts/ci/security-tests.json` in the same change. |
| gitleaks finding | Remove the secret and rotate it; it may already be in history. Add to `.gitleaksignore` only after review, using the fingerprint from the report. |
| End-to-end failure | Download `e2e-diagnostics`: screenshots, `e2e-results.json` and `compose.log`. Locally, run `npx playwright test` in `apps/web` with traces on. |
| Docker path errors on Windows | Run the scripts from Git Bash. They set `MSYS_NO_PATHCONV` and convert paths for Docker. |

---

The sections below describe the original Spring Boot prototype, which V2 replaces.
`HackerPlatform-Backend` and `HackerPlatform-UI` are superseded by `apps/api` and
`apps/web` and can be removed.

## Prerequisites

- **JDK 21** – the build uses the Java 21 toolchain defined in `build.gradle`.
- **Gradle Wrapper** – use the provided `./gradlew` script inside the `HackerPlatform-Backend` directory.

## Building

From `HackerPlatform-Backend` run:

```bash
./gradlew build
```

This compiles the source and packages the jar under `build/libs/`.

## Running Tests

From `HackerPlatform-Backend` run:

```bash
./gradlew test
```

This executes the project's unit tests.

## Starting the Application

To start the Spring Boot application execute:

```bash
./gradlew bootRun
```

The service will start locally on the default port.

## Configuration

The backend expects a signing key through the `JWT_SECRET` property. During
development you can provide it by exporting an environment variable named
`JWT_SECRET` before starting the application:

```bash
export JWT_SECRET=<your-base64-secret>
./gradlew bootRun
```

Spring Boot reads the `JWT_SECRET` variable directly, so no additional configuration is required.

## Authentication Endpoints

The backend exposes several endpoints under `/api/auth`:

- `POST /api/auth/login` – obtain an access and refresh token pair.
- `GET /api/auth/verify` – validate the current access token and session.
- `GET /api/auth/user` – retrieve details for the authenticated user.
- `GET /api/auth/validate` – returns user details if the token is valid.
- `POST /api/auth/refresh` – **new** endpoint that issues a new access token using a valid refresh token.
- `POST /api/auth/logout` – **new** endpoint that invalidates the provided refresh token.

## Frontend Development

The Next.js UI lives under `HackerPlatform-UI`.

Before running the frontend you must tell it where the backend is located. Define
an `API_URL` environment variable pointing at your backend. The easiest way is
to create a `.env.local` file inside `HackerPlatform-UI` with the line:

```bash
API_URL=http://localhost:8080
```

Adjust the URL if your backend runs elsewhere.

Install dependencies once:

```bash
cd HackerPlatform-UI
npm install
```

During development run:

```bash
npm run dev
```

This starts the app locally with hot reload enabled.

### Configuring API_URL

API requests from the UI rely on the `API_URL` environment variable. Create a
`.env.local` file inside `HackerPlatform-UI` with the following contents:

```bash
API_URL=http://localhost:8080
```

Replace the URL with the address of your backend if different. With this file in
place run the development server:

```bash
npm run dev
```

You can also override the value directly on the command line:

```bash
API_URL=http://localhost:8080 npm run dev
```
