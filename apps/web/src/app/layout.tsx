import type { Metadata } from "next";
import { connection } from "next/server";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "K9", template: "%s · K9" },
  description: "K9 security assessment console",
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  // Every page renders per request so it gets this request's CSP nonce.
  await connection();
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
