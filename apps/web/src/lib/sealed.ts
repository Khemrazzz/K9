import { EncryptJWT, jwtDecrypt } from "jose";

// Encrypted, authenticated cookie payloads (JWE, dir + A256GCM). Tampering, a wrong key
// or an expired payload all read back as null.

const encoder = new TextEncoder();

async function keyFrom(secret: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(secret)));
}

export async function seal<T extends object>(payload: T, secret: string, ttlSeconds: number): Promise<string> {
  return new EncryptJWT({ d: payload })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(`${Math.max(1, Math.floor(ttlSeconds))}s`)
    .encrypt(await keyFrom(secret));
}

export async function unseal<T>(sealed: string | undefined, secret: string): Promise<T | null> {
  if (!sealed) {
    return null;
  }
  try {
    const { payload } = await jwtDecrypt(sealed, await keyFrom(secret), {
      keyManagementAlgorithms: ["dir"],
      contentEncryptionAlgorithms: ["A256GCM"],
    });
    return (payload.d as T | undefined) ?? null;
  } catch {
    return null;
  }
}
