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

The tests read the dev password from the root `.env` and the session secret from
`apps/web/.env.local`. They sign in through the real Keycloak and cover:

- the Acme/Globex tenant boundary
- role-aware UI
- organization switching
- deep links and open-redirect attempts
- tampered, expiring and rejected sessions
- sign-out, including replaying the old cookie afterwards
- cross-site sign-out attempts, response headers, and tokens staying out of the page

`npm audit --omit=dev` reports no vulnerabilities. A full `npm audit` reports a `braces`
advisory inside ESLint's tooling. No patched version exists, and it doesn't ship to users.

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

The backend expects a signing key through the `jwt.secret` property. During
development you can provide it by exporting an environment variable named
`JWT_SECRET` before starting the application:

```bash
export JWT_SECRET=<your-base64-secret>
./gradlew bootRun
```

Spring Boot automatically maps the `JWT_SECRET` variable to the `jwt.secret`
property so no additional configuration is required.

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
