"use client";

import { useEffect, useState } from "react";

type Me = {
  id: number;
  username: string;
  role: string;
  invite_quota: number;
  is_premium: boolean;
  premium_badge_color: string;
};

export function useMe(): { me: Me | null; loaded: boolean } {
  const [me, setMe] = useState<Me | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    fetch("/api/auth/me")
      .then((res) => (res.ok ? res.json() : null))
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setLoaded(true));
  }, []);

  return { me, loaded };
}

export function useIsAdmin(): { isAdmin: boolean; loaded: boolean } {
  const { me, loaded } = useMe();
  return { isAdmin: me?.role === "admin", loaded };
}

export function AdminOnlyNotice() {
  return (
    <p className="mt-6 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
      Diese Seite ist nur fuer Administratoren verfuegbar.
    </p>
  );
}
