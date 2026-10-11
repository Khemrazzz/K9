/**
 * CSRF check for state-changing route handlers: the request must come from the app's
 * own origin. Server Actions get an equivalent check from Next.js.
 */
export function isSameOrigin(headers: Headers, appUrl: URL): boolean {
  const origin = headers.get("origin");
  if (origin) {
    return origin === appUrl.origin;
  }
  // Some browsers omit Origin on same-origin navigations; Fetch Metadata still tells us.
  return headers.get("sec-fetch-site") === "same-origin";
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: string): boolean {
  return UUID.test(value);
}
