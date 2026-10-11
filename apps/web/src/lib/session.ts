// The browser session: Keycloak tokens, sealed into HttpOnly cookies. Only the Next.js
// server can read them; client JavaScript never sees a token.

export type Session = {
  sub: string;
  accessToken: string;
  /** Epoch seconds. */
  accessTokenExpiresAt: number;
  refreshToken: string;
  /** Epoch seconds. */
  refreshTokenExpiresAt: number;
};

/** Sent only to the logout handler, as the end-session id_token_hint. */
export type IdTokenCookie = { idToken: string };

/** Short-lived state for one login round trip. */
export type LoginTransaction = {
  state: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
};

export type TokenResponse = {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
  refresh_expires_in?: number;
};

export type CookieNames = {
  session: string;
  idToken: string;
  login: string;
  organization: string;
};

/** Refresh when the access token has less than this many seconds left. */
export const REFRESH_MARGIN_SECONDS = 60;
export const LOGIN_TTL_SECONDS = 600;

export function cookieNames(secure: boolean): CookieNames {
  // __Host- cookies must be Secure, Path=/ and host-only, which also stops subdomains
  // from planting or overwriting them.
  const prefix = secure ? "__Host-" : "";
  return {
    session: `${prefix}k9_session`,
    idToken: `${prefix}k9_id`,
    login: `${prefix}k9_login`,
    organization: `${prefix}k9_org`,
  };
}

export function cookieOptions(secure: boolean, maxAgeSeconds: number) {
  return {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: "/",
    maxAge: Math.max(0, Math.floor(maxAgeSeconds)),
  };
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function needsRefresh(session: Session, now = nowSeconds()): boolean {
  return session.accessTokenExpiresAt - now < REFRESH_MARGIN_SECONDS;
}

export function isUsable(session: Session, now = nowSeconds()): boolean {
  return session.accessTokenExpiresAt > now;
}

export function sessionFromTokens(sub: string, tokens: TokenResponse, now = nowSeconds()): Session {
  if (!tokens.refresh_token) {
    throw new Error("The identity provider did not return a refresh token.");
  }
  return {
    sub,
    accessToken: tokens.access_token,
    accessTokenExpiresAt: now + (tokens.expires_in ?? 60),
    refreshToken: tokens.refresh_token,
    // Keycloak reports the refresh token's (idle) lifetime; default conservatively.
    refreshTokenExpiresAt: now + (tokens.refresh_expires_in ?? 1800),
  };
}

/** Lifetime of the session cookie: as long as the refresh token can be used. */
export function sessionTtl(session: Session, now = nowSeconds()): number {
  return Math.max(0, session.refreshTokenExpiresAt - now);
}
