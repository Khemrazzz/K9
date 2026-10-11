import { describe, expect, it } from "vitest";
import { safeReturnTo } from "./return-to";

describe("safeReturnTo", () => {
  it.each([
    ["/app", "/app"],
    ["/app/org/123", "/app/org/123"],
    ["/app/org/123?tab=members#top", "/app/org/123?tab=members#top"],
  ])("keeps console path %s", (input, expected) => {
    expect(safeReturnTo(input)).toBe(expected);
  });

  it.each([
    null,
    undefined,
    "",
    "https://evil.example/app",
    "//evil.example/app",
    "/\\evil.example/app",
    "\\\\evil.example",
    "/app\\..\\..\\evil",
    "javascript:alert(1)",
    "app/org",
    "/auth/logout",
    "/",
    "/application",
    "/app/../auth/logout",
    "/app/%2e%2e/auth/logout",
    "/app\u0000",
    "/app\n//evil.example",
    "/app\t",
    `/app/${"a".repeat(3000)}`,
  ])("falls back for %j", (input) => {
    expect(safeReturnTo(input)).toBe("/app");
  });
});
