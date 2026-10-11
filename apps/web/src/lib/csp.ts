export type CspOptions = {
  nonce: string;
  isDevelopment: boolean;
  /** The identity provider. The logout form redirects there, and form-action covers redirects. */
  issuerOrigin: string;
  upgradeInsecureRequests: boolean;
};

export function buildCsp({ nonce, isDevelopment, issuerOrigin, upgradeInsecureRequests }: CspOptions): string {
  const directives = [
    "default-src 'self'",
    // React needs eval only for dev-mode error overlays.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDevelopment ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self'${isDevelopment ? " ws:" : ""}`,
    "object-src 'none'",
    "base-uri 'self'",
    `form-action 'self' ${issuerOrigin}`,
    "frame-ancestors 'none'",
  ];
  if (upgradeInsecureRequests) {
    directives.push("upgrade-insecure-requests");
  }
  return directives.join("; ");
}

export function createNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64");
}
