import "server-only";
import { callApi } from "./dal";

// Typed calls to the K9 API. Shapes mirror apps/api/K9.Api/Organizations/OrganizationEndpoints.cs.

export const ROLES = ["Viewer", "Analyst", "Admin", "Owner"] as const;
export type Role = (typeof ROLES)[number];

export type Organization = { id: string; name: string; createdAt: string; role: Role };
export type Member = { userId: string; email: string | null; displayName: string | null; role: Role; joinedAt: string };
export type Me = { id: string; email: string | null; displayName: string | null; organizations: Organization[] };

export const getMe = () => callApi<Me>("/api/me");

export const getOrganization = (organizationId: string) =>
  callApi<Organization>(`/api/organizations/${encodeURIComponent(organizationId)}`);

export const getMembers = (organizationId: string) =>
  callApi<Member[]>(`/api/organizations/${encodeURIComponent(organizationId)}/members`);

export const createOrganization = (name: string) =>
  callApi<Organization>("/api/organizations", { method: "POST", body: { name } });

export const addMember = (organizationId: string, email: string, role: Role) =>
  callApi<Member>(`/api/organizations/${encodeURIComponent(organizationId)}/members`, {
    method: "POST",
    body: { email, role },
  });

export function roleAtLeast(role: Role, minimum: Role): boolean {
  return ROLES.indexOf(role) >= ROLES.indexOf(minimum);
}
