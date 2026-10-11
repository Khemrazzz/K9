import Link from "next/link";
import { getMe } from "@/lib/k9-api";
import { OrganizationSwitcher } from "./organization-switcher";
import { ApiUnavailable } from "./states";

export const metadata = { title: "Console" };

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const me = await getMe();

  if (!me.ok) {
    return (
      <main className="centered">
        <ApiUnavailable />
      </main>
    );
  }

  const { displayName, email, organizations } = me.data;
  return (
    <div className="shell">
      <header className="topbar">
        <Link className="brand" href="/app">
          K9
        </Link>
        {organizations.length > 0 && (
          <OrganizationSwitcher organizations={organizations.map(({ id, name, role }) => ({ id, name, role }))} />
        )}
        <span className="spacer" />
        <div className="user">
          <div>{displayName ?? email ?? "Signed in"}</div>
          {email && displayName && <div className="email">{email}</div>}
        </div>
        <form action="/auth/logout" method="post">
          <button className="button" type="submit">
            Sign out
          </button>
        </form>
      </header>
      <main className="content">{children}</main>
    </div>
  );
}
