import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';

export async function POST() {
  const refreshToken = cookies().get('refreshToken')?.value;
  if (refreshToken) {
    await fetch(`${process.env.API_URL}/api/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });
  }
  cookies().delete('accessToken');
  cookies().delete('refreshToken');
  return NextResponse.json({ success: true });
}
