import Link from "next/link";

const MESSAGES: Record<string, string> = {
  state: "Your sign-in attempt expired or was started somewhere else. Please try again.",
  callback: "The identity provider rejected the sign-in. Please try again.",
  unavailable: "The sign-in service is not reachable right now. Please try again shortly.",
};

export default async function AuthErrorPage({ searchParams }: { searchParams: Promise<{ reason?: string }> }) {
  const { reason } = await searchParams;
  const message = (reason && MESSAGES[reason]) ?? "Sign-in did not complete. Please try again.";

  return (
    <main className="centered">
      <section className="card narrow">
        <h1>Sign-in problem</h1>
        <p className="muted">{message}</p>
        <div className="actions">
          <a className="button primary" href="/auth/login">
            Try again
          </a>
          <Link className="button" href="/">
            Home
          </Link>
        </div>
      </section>
    </main>
  );
}
