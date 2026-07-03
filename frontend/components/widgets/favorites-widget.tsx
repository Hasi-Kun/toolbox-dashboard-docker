"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Star } from "lucide-react";
import { useLanguage } from "@/components/language-provider";

type Tool = { slug: string; name: string; description: string };
type Favorite = { tool_slug: string };

export function FavoritesWidget() {
  const { t } = useLanguage();
  const [favoriteTools, setFavoriteTools] = useState<Tool[] | null>(null);

  useEffect(() => {
    Promise.all([
      fetch("/api/tools").then((res) => (res.ok ? res.json() : [])),
      fetch("/api/account/favorites").then((res) => (res.ok ? res.json() : [])),
    ])
      .then(([tools, favorites]: [Tool[], Favorite[]]) => {
        const slugs = new Set(favorites.map((f) => f.tool_slug));
        setFavoriteTools(tools.filter((t) => slugs.has(t.slug)));
      })
      .catch(() => setFavoriteTools([]));
  }, []);

  return (
    <div className="rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
      <p className="text-sm text-ink-muted">{t("dashboard.favorites")}</p>

      {favoriteTools === null && <p className="mt-4 text-sm text-ink-muted">...</p>}

      {favoriteTools?.length === 0 && (
        <div className="mt-4 flex h-24 items-center justify-center rounded-lg border border-dashed border-base-border text-center text-sm text-ink-muted">
          {t("dashboard.no_favorites")}
        </div>
      )}

      {favoriteTools && favoriteTools.length > 0 && (
        <ul className="mt-3 space-y-1.5">
          {favoriteTools.map((tool) => (
            <li key={tool.slug}>
              <Link
                href={`/tools/${tool.slug}`}
                className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm text-ink hover:bg-base-border/40"
              >
                <Star className="h-3.5 w-3.5 fill-signal text-signal" />
                {tool.name}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
