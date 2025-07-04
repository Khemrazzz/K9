import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';

export async function POST() {
  const refreshToken = cookies().get('refreshToken')?.value;
  if (!refreshToken) {
    return NextResponse.json({ error: 'No refresh token' }, { status: 400 });
  }
  const res = await fetch(`${process.env.API_URL}/api/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken })
  });
  if (!res.ok) {
    return NextResponse.json({ error: 'Failed to refresh' }, { status: res.status });
  }
  const { accessToken } = await res.json();
  cookies().set('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/'
  });
  return NextResponse.json({ success: true });
}
