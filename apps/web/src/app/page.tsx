export default function HomePage() {
  return (
    <main className="centered">
      <section className="card narrow">
        <p className="brand">K9</p>
        <h1>Security assessment console</h1>
        <p className="muted">
          Sign in with your organization account to manage your organizations and members.
        </p>
        <div className="actions">
          <a className="button primary" href="/auth/login">
            Sign in
          </a>
        </div>
      </section>
    </main>
  );
}
