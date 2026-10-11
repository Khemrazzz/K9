import { NextResponse, type NextRequest } from "next/server";
import { getConfig } from "@/lib/config";
import { endSessionUrl, revokeRefreshToken } from "@/lib/oidc";
import { isSameOrigin } from "@/lib/request-guards";
import { clearSession, readIdToken, readSession } from "@/lib/session-cookies";

// POST only: signing out changes state, so it must not be triggerable by a link or image.
export async function POST(request: NextRequest) {
  const config = getConfig();
  if (!isSameOrigin(request.headers, config.appUrl)) {
    return NextResponse.json({ error: "Cross-origin request rejected." }, { status: 403 });
  }

  const session = await readSession(request.cookies, config);
  const idToken = await readIdToken(request.cookies, config);

  if (session) {
    try {
      await revokeRefreshToken(session.refreshToken);
    } catch (error) {
      console.error(`Refresh token revocation failed: ${(error as Error).name}`);
    }
  }

  let destination: URL;
  try {
    destination = await endSessionUrl(idToken);
  } catch {
    destination = new URL("/", config.appUrl);
  }

  // 303 turns the POST into a GET at Keycloak's end-session endpoint, which ends the SSO
  // session and returns to the home page.
  const response = NextResponse.redirect(destination, 303);
  clearSession(response.cookies, config);
  return response;
}
