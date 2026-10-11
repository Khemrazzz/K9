import { describe, expect, it } from "vitest";
import { cookieNames, cookieOptions, isUsable, needsRefresh, sessionFromTokens, type Session } from "./session";

const base: Session = {
  sub: "user",
  accessToken: "at",
  accessTokenExpiresAt: 1_000,
  refreshToken: "rt",
  refreshTokenExpiresAt: 2_000,
};

describe("session lifetime", () => {
  it("refreshes within a minute of expiry, not before", () => {
    expect(needsRefresh(base, 900)).toBe(false);
    expect(needsRefresh(base, 941)).toBe(true);
    expect(needsRefresh(base, 1_500)).toBe(true);
  });

  it("is usable only before the access token expires", () => {
    expect(isUsable(base, 999)).toBe(true);
    expect(isUsable(base, 1_000)).toBe(false);
  });

  it("builds a session from a token response", () => {
    const session = sessionFromTokens("sub", { access_token: "a", refresh_token: "r", expires_in: 300, refresh_expires_in: 1800 }, 100);
    expect(session).toEqual({ sub: "sub", accessToken: "a", accessTokenExpiresAt: 400, refreshToken: "r", refreshTokenExpiresAt: 1900 });
  });

  it("requires a refresh token", () => {
    expect(() => sessionFromTokens("sub", { access_token: "a" })).toThrow();
  });
});

describe("cookies", () => {
  it("uses __Host- names only when secure", () => {
    expect(cookieNames(true).session).toBe("__Host-k9_session");
    expect(cookieNames(false).session).toBe("k9_session");
  });

  it("are HttpOnly, SameSite=Lax and scoped to the whole host", () => {
    expect(cookieOptions(true, 60)).toEqual({ httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 60 });
    expect(cookieOptions(false, -5).maxAge).toBe(0);
  });
});
