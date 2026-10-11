import Link from "next/link";

// Full-panel states shared by console pages.

export function Forbidden() {
  return (
    <section className="card" role="alert">
      <h1>No access</h1>
      <p className="muted">
        You are not a member of this organization, or your role does not allow this. Ask an
        organization admin to add you.
      </p>
      <div className="actions">
        <Link className="button" href="/app">
          Back to your organizations
        </Link>
      </div>
    </section>
  );
}

export function NotFound() {
  return (
    <section className="card" role="alert">
      <h1>Not found</h1>
      <p className="muted">That organization does not exist.</p>
      <div className="actions">
        <Link className="button" href="/app">
          Back to your organizations
        </Link>
      </div>
    </section>
  );
}

export function ApiUnavailable() {
  return (
    <section className="card" role="alert">
      <h1>K9 is temporarily unavailable</h1>
      <p className="muted">The K9 API could not be reached. Your session is intact; try again in a moment.</p>
    </section>
  );
}
