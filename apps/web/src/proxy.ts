import { NextResponse, type NextRequest } from "next/server";
import { getConfig, type WebConfig } from "@/lib/config";
import { buildCsp, createNonce } from "@/lib/csp";
import { refreshTokens } from "@/lib/oidc";
import { safeReturnTo } from "@/lib/return-to";
import { isUsable, needsRefresh, nowSeconds, sessionFromTokens } from "@/lib/session";
import { clearSession, readSession, writeSession } from "@/lib/session-cookies";

// Runs before every page and route handler:
//  - sets a per-request CSP nonce and security headers;
//  - for /app, requires a session and refreshes the access token shortly before it
//    expires, writing the new cookie to both the response and this request (so the
//    page renders with the new token).
// It is a convenience layer, not the authorization boundary: pages re-check the session
// and the API authorizes every call.

export async function proxy(request: NextRequest) {
  const config = getConfig();
  const { pathname } = request.nextUrl;
  const isConsole = pathname === "/app" || pathname.startsWith("/app/");

  let refreshedCookies: { name: string; value: string; options: object }[] = [];
  if (isConsole) {
    const result = await ensureSession(request, config);
    if (result.kind === "redirect") {
      return finish(result.response, request, config, createNonce());
    }
    refreshedCookies = result.cookies;
    for (const cookie of refreshedCookies) {
      request.cookies.set(cookie.name, cookie.value);
    }
  }

  const nonce = createNonce();
  const csp = contentSecurityPolicy(config, nonce);
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("content-security-policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  for (const cookie of refreshedCookies) {
    response.cookies.set(cookie.name, cookie.value, cookie.options);
  }
  return finish(response, request, config, nonce, csp);
}

type EnsureResult =
  | { kind: "ok"; cookies: { name: string; value: string; options: object }[] }
  | { kind: "redirect"; response: NextResponse };

async function ensureSession(request: NextRequest, config: WebConfig): Promise<EnsureResult> {
  const session = await readSession(request.cookies, config);
  if (!session || session.refreshTokenExpiresAt <= nowSeconds()) {
    return { kind: "redirect", response: toLogin(request, config, session ? "expired" : undefined) };
  }
  if (!needsRefresh(session)) {
    return { kind: "ok", cookies: [] };
  }

  let tokens;
  try {
    tokens = await refreshTokens(session.refreshToken);
  } catch {
    // Identity provider unreachable. Keep going while the current token still works.
    if (isUsable(session)) {
      return { kind: "ok", cookies: [] };
    }
    const response = NextResponse.redirect(new URL("/auth/error?reason=unavailable", config.appUrl));
    return { kind: "redirect", response };
  }
  if (!tokens) {
    return { kind: "redirect", response: toLogin(request, config, "expired") };
  }

  const cookies: { name: string; value: string; options: object }[] = [];
  const jar = { set: (name: string, value: string, options: object) => void cookies.push({ name, value, options }) };
  await writeSession(jar, config, sessionFromTokens(session.sub, tokens), tokens.id_token);
  return { kind: "ok", cookies };
}

function toLogin(request: NextRequest, config: WebConfig, reason?: "expired"): NextResponse {
  const target = new URL(request.nextUrl.pathname + request.nextUrl.search, config.appUrl);
  target.searchParams.delete("_rsc");
  const login = new URL("/auth/login", config.appUrl);
  login.searchParams.set("returnTo", safeReturnTo(target.pathname + target.search));
  if (reason) {
    login.searchParams.set("reason", reason);
  }
  const response = NextResponse.redirect(login);
  clearSession(response.cookies, config);
  return response;
}

function contentSecurityPolicy(config: WebConfig, nonce: string): string {
  return buildCsp({
    nonce,
    isDevelopment: config.isDevelopment,
    issuerOrigin: config.issuer.origin,
    upgradeInsecureRequests: config.appUrl.protocol === "https:",
  });
}

function finish(response: NextResponse, request: NextRequest, config: WebConfig, nonce: string, csp = contentSecurityPolicy(config, nonce)) {
  response.headers.set("Content-Security-Policy", csp);
  const { pathname } = request.nextUrl;
  if (pathname === "/app" || pathname.startsWith("/app/") || pathname.startsWith("/auth/")) {
    // Authenticated or token-bearing responses must never be stored by browsers or proxies.
    response.headers.set("Cache-Control", "no-store, max-age=0");
  }
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
