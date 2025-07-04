import { verifySession } from '../lib/dal';
import { redirect } from 'next/navigation';

export default async function DashboardPage() {
  const session = await verifySession();
  if (!session) redirect('/login');
  return <h1>Welcome, {session.user.username}!</h1>;
}
