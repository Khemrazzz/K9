import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function POST() {
  const cookieStore = cookies();
  const refreshToken = cookieStore.get('refreshToken')?.value;
  if (refreshToken) {
    await fetch(`${process.env.API_URL}/api/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });
  }
  cookieStore.delete('accessToken');
  cookieStore.delete('refreshToken');
  return NextResponse.json({ success: true });
}
