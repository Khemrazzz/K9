import Link from "next/link";

export default function NotFoundPage() {
  return (
    <main className="centered">
      <section className="card narrow">
        <h1>Page not found</h1>
        <p className="muted">That page does not exist.</p>
        <div className="actions">
          <Link className="button" href="/">
            Home
          </Link>
        </div>
      </section>
    </main>
  );
}
