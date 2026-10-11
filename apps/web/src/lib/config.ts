// Server configuration. None of these are NEXT_PUBLIC_, so they never reach the browser.

export type WebConfig = {
  appUrl: URL;
  apiUrl: URL;
  issuer: URL;
  clientId: string;
  clientSecret: string;
  sessionSecret: string;
  /** Plain-HTTP identity provider. Local development only. */
  allowInsecureIssuer: boolean;
  /** Secure, __Host- prefixed cookies. On whenever the app is served over HTTPS. */
  secureCookies: boolean;
  isDevelopment: boolean;
};

let cached: WebConfig | undefined;

export function getConfig(): WebConfig {
  cached ??= load(process.env);
  return cached;
}

export function load(env: NodeJS.ProcessEnv): WebConfig {
  const appUrl = url(env, "K9_APP_URL");
  const issuer = url(env, "K9_OIDC_ISSUER");
  const sessionSecret = required(env, "K9_SESSION_SECRET");
  if (sessionSecret.length < 32) {
    throw new Error("K9_SESSION_SECRET must be at least 32 characters.");
  }

  const allowInsecureIssuer = env.K9_OIDC_ALLOW_HTTP === "true";
  if (issuer.protocol === "http:" && !allowInsecureIssuer) {
    throw new Error("K9_OIDC_ISSUER is plain HTTP. Set K9_OIDC_ALLOW_HTTP=true for local development only.");
  }

  return {
    appUrl,
    apiUrl: url(env, "K9_API_URL"),
    issuer,
    clientId: required(env, "K9_OIDC_CLIENT_ID"),
    clientSecret: required(env, "K9_OIDC_CLIENT_SECRET"),
    sessionSecret,
    allowInsecureIssuer,
    secureCookies: appUrl.protocol === "https:",
    isDevelopment: env.NODE_ENV === "development",
  };
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) {
    throw new Error(`${name} is not set. See apps/web/.env.example.`);
  }
  return value;
}

function url(env: NodeJS.ProcessEnv, name: string): URL {
  const value = required(env, name);
  try {
    return new URL(value);
  } catch {
    throw new Error(`${name} is not a valid URL.`);
  }
}
