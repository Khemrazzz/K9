import { describe, expect, it } from "vitest";
import { load } from "./config";
import { buildCsp } from "./csp";
import { isSameOrigin, isUuid } from "./request-guards";

const app = new URL("http://localhost:3000");

describe("isSameOrigin", () => {
  it("accepts the app's own origin", () => {
    expect(isSameOrigin(new Headers({ origin: "http://localhost:3000" }), app)).toBe(true);
  });

  it.each(["https://evil.example", "http://localhost:3001", "https://localhost:3000", "null"])("rejects %s", (origin) => {
    expect(isSameOrigin(new Headers({ origin }), app)).toBe(false);
  });

  it("falls back to Fetch Metadata when Origin is absent", () => {
    expect(isSameOrigin(new Headers({ "sec-fetch-site": "same-origin" }), app)).toBe(true);
    expect(isSameOrigin(new Headers({ "sec-fetch-site": "cross-site" }), app)).toBe(false);
    expect(isSameOrigin(new Headers(), app)).toBe(false);
  });
});

describe("isUuid", () => {
  it("accepts UUIDs only", () => {
    expect(isUuid("01a12ba1-db37-71a2-bb6c-c8dc3ea21b0c")).toBe(true);
    expect(isUuid("' OR 1=1--")).toBe(false);
    expect(isUuid("01a12ba1-db37-71a2-bb6c-c8dc3ea21b0c/../x")).toBe(false);
  });
});

describe("buildCsp", () => {
  const csp = buildCsp({ nonce: "n0nce", isDevelopment: false, issuerOrigin: "https://id.k9.test", upgradeInsecureRequests: true });

  it("allows scripts only by nonce", () => {
    expect(csp).toContain("script-src 'self' 'nonce-n0nce' 'strict-dynamic'");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toContain("unsafe-inline");
  });

  it("blocks framing and plugins and limits form targets", () => {
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("form-action 'self' https://id.k9.test");
    expect(csp).toContain("upgrade-insecure-requests");
  });
});

describe("configuration", () => {
  const env = {
    NODE_ENV: "production",
    K9_APP_URL: "https://k9.test",
    K9_API_URL: "https://api.k9.test",
    K9_OIDC_ISSUER: "https://id.k9.test/realms/k9",
    K9_OIDC_CLIENT_ID: "k9-web",
    K9_OIDC_CLIENT_SECRET: "secret",
    K9_SESSION_SECRET: "x".repeat(32),
  } as NodeJS.ProcessEnv;

  it("enables secure cookies over HTTPS", () => {
    expect(load(env).secureCookies).toBe(true);
  });

  it("refuses a short session secret", () => {
    expect(() => load({ ...env, K9_SESSION_SECRET: "short" })).toThrow(/32/);
  });

  it("refuses a plain-HTTP issuer unless explicitly allowed", () => {
    expect(() => load({ ...env, K9_OIDC_ISSUER: "http://id.k9.test/realms/k9" })).toThrow(/HTTP/);
    expect(load({ ...env, K9_OIDC_ISSUER: "http://id.k9.test/realms/k9", K9_OIDC_ALLOW_HTTP: "true" }).allowInsecureIssuer).toBe(true);
  });

  it("refuses missing settings", () => {
    expect(() => load({ ...env, K9_OIDC_CLIENT_SECRET: "" })).toThrow(/K9_OIDC_CLIENT_SECRET/);
  });
});
