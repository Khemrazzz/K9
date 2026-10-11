import { expect, test } from "@playwright/test";
import {
  ALICE,
  BOB,
  createOrganization,
  expectKeycloakLogin,
  readSessionCookie,
  SESSION_COOKIE,
  signIn,
  unique,
  writeSessionCookie,
} from "./support";

// Runs in order: later tests use organizations created by earlier ones.
test.describe.configure({ mode: "serial" });

const acme = { name: unique("Acme E2E"), id: "" };
const acmeLabs = { name: unique("Acme Labs E2E"), id: "" };
const globex = { name: unique("Globex E2E"), id: "" };

test.describe("authentication", () => {
  test("unauthenticated visitors are sent to sign in and get no data", async ({ page, request }) => {
    const direct = await request.get("/app", { maxRedirects: 0 });
    expect(direct.status()).toBe(307);
    expect(direct.headers()["location"]).toContain("/auth/login?returnTo=%2Fapp");

    await page.goto("/app");
    await expectKeycloakLogin(page);
  });

  test("a deep link survives sign-in", async ({ page }) => {
    await signIn(page, ALICE, "/app/organizations/new");
    await expect(page).toHaveURL(/\/app\/organizations\/new$/);
  });

  test("returnTo cannot send the user to another site", async ({ page }) => {
    await signIn(page, ALICE, "/auth/login?returnTo=https://evil.example/steal");
    expect(new URL(page.url()).origin).toBe("http://localhost:3000");
  });

  test("a tampered session cookie is treated as signed out", async ({ page, context }) => {
    await context.addCookies([{ name: SESSION_COOKIE, value: "tampered.value.that.is.invalid", domain: "localhost", path: "/" }]);
    await page.goto("/app");
    await expectKeycloakLogin(page);
  });
});

test.describe("tenancy", () => {
  test("Alice creates an organization and sees her own data", async ({ page }) => {
    await signIn(page, ALICE);
    acme.id = await createOrganization(page, acme.name);

    await expect(page.locator(".badge").first()).toHaveText("Owner");
    const members = page.getByRole("table");
    await expect(members).toContainText(ALICE);
    await expect(page.getByRole("heading", { name: "Add a member" })).toBeVisible();
  });

  test("Bob creates his own organization and cannot open Alice's", async ({ page }) => {
    await signIn(page, BOB);
    globex.id = await createOrganization(page, globex.name);

    await page.goto(`/app/org/${acme.id}`);
    await expect(page.getByRole("heading", { name: "No access" })).toBeVisible();
    await expect(page.getByText(acme.name)).toHaveCount(0);

    const options = await page.locator("#organization-switcher option").allTextContents();
    expect(options.join("\n")).not.toContain(acme.name);
  });

  test("organization switching follows the API's membership list", async ({ page }) => {
    await signIn(page, ALICE);
    acmeLabs.id = await createOrganization(page, acmeLabs.name);

    await page.locator("#organization-switcher").selectOption(acme.id);
    await expect(page).toHaveURL(new RegExp(`/app/org/${acme.id}$`));
    await expect(page.getByRole("heading", { level: 1, name: acme.name })).toBeVisible();

    // The console home resumes the last organization chosen.
    await page.goto("/app");
    await expect(page).toHaveURL(new RegExp(`/app/org/${acme.id}$`));

    const options = await page.locator("#organization-switcher option").allTextContents();
    expect(options.join("\n")).not.toContain(globex.name);
  });

  test("a viewer sees the organization but not the admin controls", async ({ page, browser }) => {
    await signIn(page, ALICE, `/app/org/${acmeLabs.id}`);
    await page.getByLabel("Email").fill(BOB);
    await page.getByLabel("Role").selectOption("Viewer");
    await page.getByRole("button", { name: "Add member" }).click();
    await expect(page.getByRole("status")).toContainText(`${BOB} was added as Viewer`);

    const bobContext = await browser.newContext();
    const bob = await bobContext.newPage();
    await signIn(bob, BOB, `/app/org/${acmeLabs.id}`);
    await expect(bob.getByRole("heading", { level: 1, name: acmeLabs.name })).toBeVisible();
    await expect(bob.locator(".badge").first()).toHaveText("Viewer");
    await expect(bob.getByRole("heading", { name: "Add a member" })).toHaveCount(0);
    // Still no access to Alice's other organization.
    await bob.goto(`/app/org/${acme.id}`);
    await expect(bob.getByRole("heading", { name: "No access" })).toBeVisible();
    await bobContext.close();
  });
});

test.describe("session lifecycle", () => {
  test("an expiring access token is refreshed and the refresh token rotated", async ({ page, context }) => {
    await signIn(page, ALICE);
    const before = await readSessionCookie(context);
    await writeSessionCookie(context, { ...before, accessTokenExpiresAt: Math.floor(Date.now() / 1000) - 1 });

    await page.goto(`/app/org/${acme.id}`);
    await expect(page.getByRole("heading", { level: 1, name: acme.name })).toBeVisible();

    const after = await readSessionCookie(context);
    expect(after.accessTokenExpiresAt).toBeGreaterThan(Date.now() / 1000);
    expect(after.refreshToken).not.toBe(before.refreshToken);
  });

  test("a session whose refresh is rejected must sign in again", async ({ browser }) => {
    // Fresh context: no Keycloak SSO cookie, so re-authentication cannot happen silently.
    const context = await browser.newContext();
    const page = await context.newPage();
    const now = Math.floor(Date.now() / 1000);
    await writeSessionCookie(context, {
      sub: "someone",
      accessToken: "expired",
      accessTokenExpiresAt: now - 10,
      refreshToken: "not-a-real-refresh-token",
      refreshTokenExpiresAt: now + 600,
    });

    await page.goto("/app");
    await expectKeycloakLogin(page);
    expect((await context.cookies()).find((c) => c.name === SESSION_COOKIE)).toBeUndefined();
    await context.close();
  });

  test("sign-out ends the session here and at Keycloak, and the old refresh token stops working", async ({ page, context }) => {
    await signIn(page, ALICE);
    const before = await readSessionCookie(context);

    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page).toHaveURL("http://localhost:3000/");
    expect((await context.cookies()).find((c) => c.name === SESSION_COOKIE)).toBeUndefined();

    // The Keycloak SSO session is gone too: signing in asks for credentials again.
    await page.goto("/app");
    await expectKeycloakLogin(page);

    // Replaying the old cookie fails once its access token is spent: its refresh token no longer works.
    await writeSessionCookie(context, { ...before, accessTokenExpiresAt: Math.floor(Date.now() / 1000) - 1 });
    await page.goto("/app");
    await expectKeycloakLogin(page);
  });
});

test.describe("request hardening", () => {
  test("sign-out rejects cross-site requests", async ({ request }) => {
    const forged = await request.post("/auth/logout", { headers: { Origin: "https://evil.example" }, maxRedirects: 0 });
    expect(forged.status()).toBe(403);
  });

  test("authenticated pages are not cacheable and carry a strict CSP", async ({ page }) => {
    await signIn(page, ALICE);
    const response = await page.goto(`/app/org/${acme.id}`);
    const headers = response!.headers();
    expect(headers["cache-control"]).toContain("no-store");
    expect(headers["content-security-policy"]).toMatch(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
    expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(headers["x-frame-options"]).toBe("DENY");
  });

  test("tokens never reach the browser", async ({ page, context }) => {
    await signIn(page, ALICE);
    const session = await readSessionCookie(context);
    const html = await page.content();
    const scriptVisible = await page.evaluate(() => document.cookie);

    expect(html).not.toContain(session.accessToken);
    expect(html).not.toContain(session.refreshToken);
    expect(scriptVisible).not.toContain("k9_");
  });
});
