"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { getConfig } from "@/lib/config";
import type { ApiFailure } from "@/lib/dal";
import * as k9 from "@/lib/k9-api";
import { isUuid } from "@/lib/request-guards";
import { cookieNames, cookieOptions } from "@/lib/session";

// Server Actions. Each one goes through the data access layer, which re-reads the session;
// the API then authorizes the call. Next.js rejects Server Action calls whose Origin does
// not match the host (CSRF).

export type FormState = { error?: string; success?: string };

const ORGANIZATION_COOKIE_TTL = 60 * 60 * 24 * 30;

export async function selectOrganization(formData: FormData): Promise<void> {
  const organizationId = String(formData.get("organizationId") ?? "");
  const me = await k9.getMe();
  // Only remember organizations the API lists for this user. The cookie is a preference,
  // not a permission: every page load is authorized by the API.
  if (!me.ok || !me.data.organizations.some((o) => o.id === organizationId)) {
    redirect("/app");
  }
  await rememberOrganization(organizationId);
  redirect(`/app/org/${organizationId}`);
}

export async function createOrganization(_: FormState, formData: FormData): Promise<FormState> {
  const name = String(formData.get("name") ?? "").trim();
  if (name.length === 0 || name.length > 200) {
    return { error: "Enter a name of up to 200 characters." };
  }

  const result = await k9.createOrganization(name);
  if (!result.ok) {
    return { error: describeFailure(result) };
  }
  await rememberOrganization(result.data.id);
  redirect(`/app/org/${result.data.id}`);
}

export async function addMember(organizationId: string, _: FormState, formData: FormData): Promise<FormState> {
  if (!isUuid(organizationId)) {
    return { error: "Unknown organization." };
  }
  const email = String(formData.get("email") ?? "").trim();
  const role = String(formData.get("role") ?? "");
  if (!email || !(k9.ROLES as readonly string[]).includes(role)) {
    return { error: "Enter an email address and choose a role." };
  }

  const result = await k9.addMember(organizationId, email, role as k9.Role);
  if (!result.ok) {
    return { error: describeFailure(result) };
  }
  revalidatePath(`/app/org/${organizationId}`);
  return { success: `${email} was added as ${role}.` };
}

async function rememberOrganization(organizationId: string) {
  const config = getConfig();
  (await cookies()).set(
    cookieNames(config.secureCookies).organization,
    organizationId,
    cookieOptions(config.secureCookies, ORGANIZATION_COOKIE_TTL),
  );
}

function describeFailure(failure: ApiFailure): string {
  switch (failure.kind) {
    case "forbidden":
      return failure.detail ?? "You do not have permission to do that.";
    case "not-found":
      return failure.detail ?? "Not found.";
    case "conflict":
      return failure.detail ?? "That already exists.";
    case "invalid":
      return failure.detail ?? "The request was not valid.";
    case "unavailable":
      return "K9 is temporarily unavailable. Please try again.";
  }
}
