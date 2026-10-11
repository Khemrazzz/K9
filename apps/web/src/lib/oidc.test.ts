import { describe, expect, it, vi } from "vitest";
import { createRefresher } from "./oidc";
import type { TokenResponse } from "./session";

const tokens: TokenResponse = { access_token: "new-at", refresh_token: "new-rt", expires_in: 300 };

describe("createRefresher", () => {
  it("sends one refresh for concurrent callers with the same token", async () => {
    let release!: (value: TokenResponse) => void;
    const grant = vi.fn(() => new Promise<TokenResponse>((resolve) => (release = resolve)));
    const refresh = createRefresher(grant);

    const results = Promise.all([refresh("rt-1"), refresh("rt-1"), refresh("rt-1")]);
    release(tokens);

    expect(await results).toEqual([tokens, tokens, tokens]);
    expect(grant).toHaveBeenCalledTimes(1);
  });

  it("refreshes different tokens independently", async () => {
    const grant = vi.fn(async () => tokens);
    const refresh = createRefresher(grant);
    await Promise.all([refresh("rt-a"), refresh("rt-b")]);
    expect(grant).toHaveBeenCalledTimes(2);
  });

  it("ends the session when the provider rejects the token", async () => {
    const refresh = createRefresher(async () => {
      throw Object.assign(new Error("invalid_grant"), { error: "invalid_grant" });
    });
    expect(await refresh("revoked")).toBeNull();
  });

  it("surfaces network failures instead of ending the session", async () => {
    const refresh = createRefresher(async () => {
      throw new TypeError("fetch failed");
    });
    await expect(refresh("rt")).rejects.toThrow("fetch failed");
  });
});
