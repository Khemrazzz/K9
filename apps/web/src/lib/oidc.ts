import * as client from "openid-client";
import { getConfig, type WebConfig } from "./config";
import type { LoginTransaction, TokenResponse } from "./session";

// Keycloak via OpenID Connect: authorization code flow with PKCE, nonce and state, as a
// confidential client. The client secret stays on this server.

let discovered: Promise<client.Configuration> | undefined;

function oidc(config: WebConfig = getConfig()): Promise<client.Configuration> {
  discovered ??= client
    .discovery(config.issuer, config.clientId, undefined, client.ClientSecretPost(config.clientSecret), {
      execute: config.allowInsecureIssuer ? [client.allowInsecureRequests] : [],
    })
    .catch((error: unknown) => {
      discovered = undefined; // retry discovery on the next request
      throw error;
    });
  return discovered;
}

function redirectUri(config: WebConfig): string {
  return new URL("/auth/callback", config.appUrl).toString();
}

export async function startLogin(returnTo: string): Promise<{ url: URL; transaction: LoginTransaction }> {
  const config = getConfig();
  const transaction: LoginTransaction = {
    state: client.randomState(),
    nonce: client.randomNonce(),
    codeVerifier: client.randomPKCECodeVerifier(),
    returnTo,
  };
  const url = client.buildAuthorizationUrl(await oidc(config), {
    redirect_uri: redirectUri(config),
    scope: "openid",
    state: transaction.state,
    nonce: transaction.nonce,
    code_challenge: await client.calculatePKCECodeChallenge(transaction.codeVerifier),
    code_challenge_method: "S256",
  });
  return { url, transaction };
}

/** Validates state, PKCE, nonce and the ID token, then returns the tokens and subject. */
export async function finishLogin(
  search: string,
  transaction: LoginTransaction,
): Promise<{ sub: string; tokens: TokenResponse }> {
  const config = getConfig();
  // Rebuild the callback URL from configuration rather than trusting Host headers.
  const callbackUrl = new URL(`/auth/callback${search}`, config.appUrl);
  const tokens = await client.authorizationCodeGrant(await oidc(config), callbackUrl, {
    pkceCodeVerifier: transaction.codeVerifier,
    expectedState: transaction.state,
    expectedNonce: transaction.nonce,
    idTokenExpected: true,
  });
  const sub = tokens.claims()?.sub;
  if (!sub) {
    throw new Error("ID token has no subject.");
  }
  return { sub, tokens: tokens as TokenResponse };
}

export type RefreshGrant = (refreshToken: string) => Promise<TokenResponse>;

/**
 * Wraps a refresh grant so concurrent refreshes of the same token share one request.
 * Keycloak rotates refresh tokens and rejects reuse, so two parallel refreshes would
 * otherwise end the session. Resolves to null when the provider rejects the token
 * (expired, revoked, reused); network failures still throw.
 */
export function createRefresher(grant: RefreshGrant): (refreshToken: string) => Promise<TokenResponse | null> {
  const inFlight = new Map<string, Promise<TokenResponse | null>>();
  return (refreshToken) => {
    const existing = inFlight.get(refreshToken);
    if (existing) {
      return existing;
    }
    const attempt = grant(refreshToken)
      .then((tokens): TokenResponse | null => tokens)
      .catch((error: unknown) => {
        if (error instanceof client.ResponseBodyError || isOAuthError(error)) {
          return null;
        }
        throw error;
      })
      .finally(() => {
        // Keep the result briefly so requests that raced the first one reuse it.
        setTimeout(() => inFlight.delete(refreshToken), 10_000).unref?.();
      });
    inFlight.set(refreshToken, attempt);
    return attempt;
  };
}

function isOAuthError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "error" in error && typeof error.error === "string";
}

export const refreshTokens = createRefresher(async (refreshToken) =>
  (await client.refreshTokenGrant(await oidc(), refreshToken)) as TokenResponse,
);

/** Best effort: ends the refresh token at the provider. */
export async function revokeRefreshToken(refreshToken: string): Promise<void> {
  await client.tokenRevocation(await oidc(), refreshToken, { token_type_hint: "refresh_token" });
}

export async function endSessionUrl(idToken: string | undefined): Promise<URL> {
  const config = getConfig();
  const home = new URL("/", config.appUrl).toString();
  if (!idToken) {
    return new URL(home);
  }
  return client.buildEndSessionUrl(await oidc(config), {
    id_token_hint: idToken,
    post_logout_redirect_uri: home,
  });
}
