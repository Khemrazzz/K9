export const metadata = {
  title: 'HackerPlatform',
  description: 'Frontend for HackerPlatform',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
