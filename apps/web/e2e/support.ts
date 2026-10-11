import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, type BrowserContext, type Page } from "@playwright/test";
import { seal, unseal } from "../src/lib/sealed";
import type { Session } from "../src/lib/session";

// Secrets come from the local env files, never from the repository.
function readEnv(path: string): Record<string, string> {
  if (!existsSync(path)) {
    throw new Error(`Missing ${path}. See the README for end-to-end test setup.`);
  }
  return Object.fromEntries(
    readFileSync(path, "utf8")
      .split(/\r?\n/)
      .filter((line) => line.includes("=") && !line.trimStart().startsWith("#"))
      .map((line) => [line.slice(0, line.indexOf("=")).trim(), line.slice(line.indexOf("=") + 1).trim()]),
  );
}

const rootEnv = readEnv(resolve(__dirname, "../../../.env"));
const webEnv = readEnv(resolve(__dirname, "../.env.local"));

export const devPassword = rootEnv.K9_DEV_USER_PASSWORD!;
const sessionSecret = webEnv.K9_SESSION_SECRET!;

export const ALICE = "alice@acme.test";
export const BOB = "bob@globex.test";
export const SESSION_COOKIE = "k9_session";

export function unique(prefix: string): string {
  return `${prefix} ${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
}

export async function expectKeycloakLogin(page: Page) {
  await expect(page).toHaveURL(/localhost:8081\/realms\/k9\/protocol\/openid-connect\/auth/);
  await expect(page.locator("#username")).toBeVisible();
}

/** Opens `path` (default /app), signs in on the Keycloak page and waits to land back in the console. */
export async function signIn(page: Page, email: string, path = "/app") {
  await page.goto(path);
  await expectKeycloakLogin(page);
  await page.locator("#username").fill(email);
  await page.locator("#password").fill(devPassword);
  await page.locator("#kc-login").click();
  await expect(page).toHaveURL(/localhost:3000\/app/);
}

export async function createOrganization(page: Page, name: string): Promise<string> {
  await page.goto("/app/organizations/new");
  await page.getByLabel("Organization name").fill(name);
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const id = page.url().split("/app/org/")[1];
  expect(id).toMatch(/^[0-9a-f-]{36}$/);
  return id!;
}

export async function readSessionCookie(context: BrowserContext): Promise<Session> {
  const cookie = (await context.cookies()).find((c) => c.name === SESSION_COOKIE);
  const session = await unseal<Session>(cookie?.value, sessionSecret);
  if (!session) {
    throw new Error("No valid session cookie.");
  }
  return session;
}

/** Replaces the session cookie with a modified copy, sealed with the app's key. */
export async function writeSessionCookie(context: BrowserContext, session: Session) {
  await context.addCookies([
    {
      name: SESSION_COOKIE,
      value: await seal(session, sessionSecret, 1800),
      domain: "localhost",
      path: "/",
      httpOnly: true,
      sameSite: "Lax",
    },
  ]);
}
