import type { WebConfig } from "./config";
import { seal, unseal } from "./sealed";
import {
  cookieNames,
  cookieOptions,
  sessionTtl,
  type IdTokenCookie,
  type Session,
} from "./session";

type CookieReader = { get(name: string): { value: string } | undefined };
type CookieWriter = {
  set(name: string, value: string, options: ReturnType<typeof cookieOptions>): unknown;
};

export async function readSession(cookies: CookieReader, config: WebConfig): Promise<Session | null> {
  const names = cookieNames(config.secureCookies);
  return unseal<Session>(cookies.get(names.session)?.value, config.sessionSecret);
}

export async function readIdToken(cookies: CookieReader, config: WebConfig): Promise<string | undefined> {
  const names = cookieNames(config.secureCookies);
  return (await unseal<IdTokenCookie>(cookies.get(names.idToken)?.value, config.sessionSecret))?.idToken;
}

/** Seals the session (and ID token, if given) and returns the cookie values written. */
export async function writeSession(
  cookies: CookieWriter,
  config: WebConfig,
  session: Session,
  idToken: string | undefined,
): Promise<{ session: string; idToken?: string }> {
  const names = cookieNames(config.secureCookies);
  const ttl = sessionTtl(session);
  const sealedSession = await seal(session, config.sessionSecret, ttl);
  cookies.set(names.session, sealedSession, cookieOptions(config.secureCookies, ttl));

  let sealedIdToken: string | undefined;
  if (idToken) {
    sealedIdToken = await seal({ idToken } satisfies IdTokenCookie, config.sessionSecret, ttl);
    cookies.set(names.idToken, sealedIdToken, cookieOptions(config.secureCookies, ttl));
  }
  return { session: sealedSession, idToken: sealedIdToken };
}

/**
 * Expires the session cookies. Overwrites with full attributes rather than deleting:
 * browsers ignore a __Host- cookie update that lacks Secure and Path=/.
 */
export function clearSession(cookies: CookieWriter, config: WebConfig): void {
  const names = cookieNames(config.secureCookies);
  for (const name of [names.session, names.idToken, names.organization]) {
    cookies.set(name, "", cookieOptions(config.secureCookies, 0));
  }
}
