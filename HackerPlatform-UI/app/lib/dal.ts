import { cache } from 'react';
import { cookies } from 'next/headers';
import { POST as refreshTokens } from '../api/auth/refresh/route';

export const verifySession = cache(async () => {
  const cookieStore = cookies();
  let token = cookieStore.get('accessToken')?.value;
  if (!token) return null;
  try {
    let res = await fetch(`${process.env.API_URL}/api/auth/validate`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (res.ok) return await res.json();
    if (res.status === 401) {
      const refreshRes = await refreshTokens();
      if (refreshRes.ok) {
        const { accessToken } = await refreshRes.json();
        token = accessToken;
        res = await fetch(`${process.env.API_URL}/api/auth/validate`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (res.ok) return await res.json();
      }
    }
    return null;
  } catch {
    return null;
  }
});
