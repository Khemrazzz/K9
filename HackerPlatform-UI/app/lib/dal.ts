import { cache } from 'react';
import { cookies } from 'next/headers';

export const verifySession = cache(async () => {
  const token = cookies().get('accessToken')?.value;
  if (!token) return null;
  try {
    const res = await fetch(`${process.env.API_URL}/api/auth/verify`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return res.ok ? await res.json() : null;
  } catch {
    return null;
  }
});
