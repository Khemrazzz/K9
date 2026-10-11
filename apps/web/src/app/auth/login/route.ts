import { NextResponse, type NextRequest } from "next/server";
import { getConfig } from "@/lib/config";
import { startLogin } from "@/lib/oidc";
import { safeReturnTo } from "@/lib/return-to";
import { seal } from "@/lib/sealed";
import { cookieNames, cookieOptions, LOGIN_TTL_SECONDS } from "@/lib/session";

export async function GET(request: NextRequest) {
  const config = getConfig();
  const returnTo = safeReturnTo(request.nextUrl.searchParams.get("returnTo"));

  let login;
  try {
    login = await startLogin(returnTo);
  } catch (error) {
    console.error(`Sign-in could not start: ${(error as Error).message}`);
    return NextResponse.redirect(new URL("/auth/error?reason=unavailable", config.appUrl));
  }

  const response = NextResponse.redirect(login.url);
  response.cookies.set(
    cookieNames(config.secureCookies).login,
    await seal(login.transaction, config.sessionSecret, LOGIN_TTL_SECONDS),
    cookieOptions(config.secureCookies, LOGIN_TTL_SECONDS),
  );
  return response;
}
