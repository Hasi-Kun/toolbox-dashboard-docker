"use client";

import { useEffect, useState } from "react";
import { Users } from "lucide-react";

type OnlineUsers = { count: number; usernames: string[] };

export function OnlineUsersWidget() {
  const [data, setData] = useState<OnlineUsers | null>(null);

  useEffect(() => {
    function load() {
      fetch("/api/system/online-users")
        .then((res) => (res.ok ? res.json() : null))
        .then(setData)
        .catch(() => setData(null));
    }
    load();
    const interval = setInterval(load, 20000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
      <div className="flex items-center gap-2 text-ink-muted">
        <Users className="h-4 w-4" />
        <span className="text-sm">Online</span>
      </div>
      <p className="mt-2 font-display text-2xl text-ink">{data ? data.count : "—"}</p>
      {data && data.usernames.length > 0 && (
        <p className="mt-1 truncate text-xs text-ink-muted" title={data.usernames.join(", ")}>
          {data.usernames.join(", ")}
        </p>
      )}
    </div>
  );
}
