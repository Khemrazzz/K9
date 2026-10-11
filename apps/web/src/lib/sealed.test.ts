import { describe, expect, it } from "vitest";
import { seal, unseal } from "./sealed";

const secret = "a".repeat(48);

describe("sealed cookies", () => {
  it("round-trips a payload", async () => {
    const sealed = await seal({ accessToken: "at", n: 1 }, secret, 60);
    expect(await unseal(sealed, secret)).toEqual({ accessToken: "at", n: 1 });
  });

  it("does not expose the payload in the cookie value", async () => {
    const sealed = await seal({ accessToken: "super-secret-token" }, secret, 60);
    expect(sealed).not.toContain("super-secret-token");
    expect(Buffer.from(sealed.split(".")[3] ?? "", "base64url").toString()).not.toContain("super-secret-token");
  });

  it("rejects a different key", async () => {
    const sealed = await seal({ v: 1 }, secret, 60);
    expect(await unseal(sealed, "b".repeat(48))).toBeNull();
  });

  it("rejects tampering", async () => {
    const sealed = await seal({ v: 1 }, secret, 60);
    const parts = sealed.split(".");
    const ciphertext = parts[3]!;
    parts[3] = (ciphertext[0] === "A" ? "B" : "A") + ciphertext.slice(1);
    expect(await unseal(parts.join("."), secret)).toBeNull();
  });

  it("rejects an expired payload", async () => {
    const sealed = await seal({ v: 1 }, secret, 1);
    await new Promise((resolve) => setTimeout(resolve, 2100));
    expect(await unseal(sealed, secret)).toBeNull();
  });

  it.each([undefined, "", "garbage", "a.b.c.d.e", "eyJhbGciOiJub25lIn0.e30."])("rejects %j", async (value) => {
    expect(await unseal(value, secret)).toBeNull();
  });
});
