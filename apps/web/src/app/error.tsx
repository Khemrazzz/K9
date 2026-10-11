"use client";

export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  // Error details stay in server logs; the browser only learns that something failed.
  return (
    <main className="centered">
      <section className="card narrow" role="alert">
        <h1>Something went wrong</h1>
        <p className="muted">K9 could not complete that request. Please try again.</p>
        <div className="actions">
          <button className="button primary" type="button" onClick={reset}>
            Try again
          </button>
          <a className="button" href="/app">
            Console home
          </a>
        </div>
      </section>
    </main>
  );
}
