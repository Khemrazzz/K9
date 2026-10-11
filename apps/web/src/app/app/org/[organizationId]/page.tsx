import Link from "next/link";
import { notFound } from "next/navigation";
import { getMembers, getOrganization, roleAtLeast, ROLES } from "@/lib/k9-api";
import { isUuid } from "@/lib/request-guards";
import { ApiUnavailable, Forbidden, NotFound } from "../../states";
import { AddMemberForm } from "./add-member-form";

export const metadata = { title: "Organization" };

const dateFormat = new Intl.DateTimeFormat("en", { dateStyle: "medium" });

export default async function OrganizationPage({ params }: { params: Promise<{ organizationId: string }> }) {
  const { organizationId } = await params;
  if (!isUuid(organizationId)) {
    notFound();
  }

  // The API decides access. A 403 here is the tenant boundary doing its job.
  const [organization, members] = await Promise.all([getOrganization(organizationId), getMembers(organizationId)]);
  if (!organization.ok) {
    switch (organization.kind) {
      case "forbidden":
        return <Forbidden />;
      case "not-found":
        return <NotFound />;
      default:
        return <ApiUnavailable />;
    }
  }
  if (!members.ok) {
    return members.kind === "forbidden" ? <Forbidden /> : <ApiUnavailable />;
  }

  const { name, role, createdAt } = organization.data;
  // Showing the form is a convenience; the API enforces who may add members and which roles.
  const canManageMembers = roleAtLeast(role, "Admin");
  const grantableRoles = ROLES.filter((r) => roleAtLeast(role, r));

  return (
    <>
      <div className="page-header">
        <div>
          <h1>{name}</h1>
          <p className="muted">
            Your role: <span className="badge">{role}</span>
          </p>
        </div>
        <Link className="button" href="/app/organizations/new">
          New organization
        </Link>
      </div>

      <section className="card">
        <h2>Overview</h2>
        <dl className="facts">
          <dt>Created</dt>
          <dd>{dateFormat.format(new Date(createdAt))}</dd>
          <dt>Members</dt>
          <dd>{members.data.length}</dd>
          <dt>Organization ID</dt>
          <dd>
            <code>{organizationId}</code>
          </dd>
        </dl>
      </section>

      <section className="card">
        <h2>Members</h2>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Joined</th>
            </tr>
          </thead>
          <tbody>
            {members.data.map((member) => (
              <tr key={member.userId}>
                <td>{member.displayName ?? "—"}</td>
                <td>{member.email ?? "—"}</td>
                <td>
                  <span className="badge">{member.role}</span>
                </td>
                <td>{dateFormat.format(new Date(member.joinedAt))}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {canManageMembers && (
        <section className="card">
          <h2>Add a member</h2>
          <p className="muted">The person must have signed in to K9 at least once.</p>
          <AddMemberForm organizationId={organizationId} roles={grantableRoles} />
        </section>
      )}
    </>
  );
}
