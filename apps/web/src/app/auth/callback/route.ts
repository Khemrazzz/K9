import { NextResponse, type NextRequest } from "next/server";
import { getConfig } from "@/lib/config";
import { finishLogin } from "@/lib/oidc";
import { safeReturnTo } from "@/lib/return-to";
import { unseal } from "@/lib/sealed";
import { cookieNames, cookieOptions, sessionFromTokens, type LoginTransaction } from "@/lib/session";
import { writeSession } from "@/lib/session-cookies";

export async function GET(request: NextRequest) {
  const config = getConfig();
  const names = cookieNames(config.secureCookies);
  const transaction = await unseal<LoginTransaction>(request.cookies.get(names.login)?.value, config.sessionSecret);

  const fail = (reason: string) => {
    const response = NextResponse.redirect(new URL(`/auth/error?reason=${reason}`, config.appUrl));
    response.cookies.set(names.login, "", cookieOptions(config.secureCookies, 0));
    return response;
  };

  // No (or a tampered, expired) login transaction: this callback was not started here.
  if (!transaction) {
    return fail("state");
  }

  let result;
  try {
    result = await finishLogin(request.nextUrl.search, transaction);
  } catch (error) {
    // Log the failure type only; never the URL, which carries the authorization code.
    console.error(`Sign-in callback rejected: ${(error as Error).name}`);
    return fail("callback");
  }

  const response = NextResponse.redirect(new URL(safeReturnTo(transaction.returnTo), config.appUrl));
  response.cookies.set(names.login, "", cookieOptions(config.secureCookies, 0));
  await writeSession(response.cookies, config, sessionFromTokens(result.sub, result.tokens), result.tokens.id_token);
  return response;
}
