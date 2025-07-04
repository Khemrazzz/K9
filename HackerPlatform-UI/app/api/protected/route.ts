import { NextResponse } from 'next/server';
import { verifySession } from '../../lib/dal';

export async function GET() {
  const session = await verifySession();
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  return NextResponse.json({ data: `Secret data for ${session.user.username}` });
}
