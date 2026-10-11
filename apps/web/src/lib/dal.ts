import "server-only";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { getConfig } from "./config";
import { isUsable, type Session } from "./session";
import { readSession } from "./session-cookies";

// Data access layer. Every read of the session and every API call goes through here.
// The API decides what the user may see; this layer only attaches their token and turns
// responses into results the UI can render.

export async function requireSession(): Promise<Session> {
  const session = await readSession(await cookies(), getConfig());
  if (!session) {
    redirect("/auth/login");
  }
  if (!isUsable(session)) {
    // The proxy refreshes before expiry; reaching this means refresh was not possible.
    redirect("/auth/login?reason=expired");
  }
  return session;
}

export type ApiFailure =
  | { ok: false; kind: "forbidden" | "not-found" | "conflict" | "invalid"; detail?: string }
  | { ok: false; kind: "unavailable" };

export type ApiResult<T> = { ok: true; data: T } | ApiFailure;

const TIMEOUT_MS = 10_000;

export async function callApi<T>(path: string, init: { method?: "GET" | "POST"; body?: unknown } = {}): Promise<ApiResult<T>> {
  const session = await requireSession();
  const config = getConfig();

  let response: Response;
  try {
    response = await fetch(new URL(path, config.apiUrl), {
      method: init.method ?? "GET",
      headers: {
        Authorization: `Bearer ${session.accessToken}`,
        Accept: "application/json",
        ...(init.body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      cache: "no-store",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    console.error(`K9 API unreachable: ${init.method ?? "GET"} ${path}: ${(error as Error).name}`);
    return { ok: false, kind: "unavailable" };
  }

  if (response.ok) {
    return { ok: true, data: (await response.json()) as T };
  }
  if (response.status === 401) {
    redirect("/auth/login?reason=expired");
  }

  const detail = await problemDetail(response);
  switch (response.status) {
    case 400:
      return { ok: false, kind: "invalid", detail };
    case 403:
      return { ok: false, kind: "forbidden", detail };
    case 404:
      return { ok: false, kind: "not-found", detail };
    case 409:
      return { ok: false, kind: "conflict", detail };
    default:
      console.error(`K9 API error: ${init.method ?? "GET"} ${path} returned ${response.status}`);
      return { ok: false, kind: "unavailable" };
  }
}

async function problemDetail(response: Response): Promise<string | undefined> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    return typeof body.detail === "string" ? body.detail : undefined;
  } catch {
    return undefined;
  }
}
