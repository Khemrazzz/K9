const DEFAULT_RETURN_TO = "/app";
const BASE = "http://k9.invalid";

/**
 * Returns a same-origin path inside the console, or the default. Anything that could
 * leave the site (absolute or protocol-relative URLs, backslash tricks, control
 * characters) or point outside /app falls back to the default.
 */
export function safeReturnTo(value: string | null | undefined, fallback = DEFAULT_RETURN_TO): string {
  if (!value || value.length > 2048) {
    return fallback;
  }
  // Only plain paths. Browsers treat "//host" and "/\host" as other origins.
  if (!value.startsWith("/") || value.startsWith("//") || value.includes("\\")) {
    return fallback;
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    return fallback;
  }

  let parsed: URL;
  try {
    parsed = new URL(value, BASE);
  } catch {
    return fallback;
  }
  if (parsed.origin !== BASE) {
    return fallback;
  }
  if (parsed.pathname !== "/app" && !parsed.pathname.startsWith("/app/")) {
    return fallback;
  }
  return `${parsed.pathname}${parsed.search}${parsed.hash}`;
}
