"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Languages, LogOut, Search, Star, X } from "lucide-react";
import { useLanguage } from "@/components/language-provider";
import type { TranslationKey } from "@/lib/i18n";
import { StyledUsername } from "@/components/styled-username";
import { WebCliManager } from "@/components/webcli/webcli-manager";

type Me = {
  id: number; username: string; role: string; has_2fa: boolean; is_premium: boolean; premium_badge_color: string;
  display_name_style: string; display_name_color: string; display_name_gradient_color: string;
};
type Tool = { slug: string; name: string; description: string; category: string };
type Favorite = { tool_slug: string };

export function Topbar() {
  const router = useRouter();
  const { language, setLanguage, t } = useLanguage();
  const [me, setMe] = useState<Me | null>(null);
  const [tools, setTools] = useState<Tool[]>([]);
  const [favorites, setFavorites] = useState<Favorite[]>([]);

  const [query, setQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [favoritesOpen, setFavoritesOpen] = useState(false);

  const searchRef = useRef<HTMLDivElement>(null);
  const favoritesRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/auth/me")
      .then((res) => (res.ok ? res.json() : null))
      .then(setMe)
      .catch(() => setMe(null));
    fetch("/api/tools")
      .then((res) => (res.ok ? res.json() : []))
      .then(setTools)
      .catch(() => setTools([]));
    refreshFavorites();
  }, []);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) setSearchOpen(false);
      if (favoritesRef.current && !favoritesRef.current.contains(e.target as Node)) setFavoritesOpen(false);
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  function refreshFavorites() {
    fetch("/api/account/favorites")
      .then((res) => (res.ok ? res.json() : []))
      .then(setFavorites)
      .catch(() => setFavorites([]));
  }

  async function handleLogout() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/login");
    router.refresh();
  }

  async function toggleFavorite(slug: string, isFavorite: boolean) {
    if (isFavorite) {
      await fetch(`/api/account/favorites/${slug}`, { method: "DELETE" });
    } else {
      await fetch("/api/account/favorites", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tool_slug: slug }),
      });
    }
    refreshFavorites();
  }

  const matches =
    query.trim().length > 0
      ? tools
          .filter(
            (t) =>
              t.name.toLowerCase().includes(query.toLowerCase()) ||
              t.description.toLowerCase().includes(query.toLowerCase()) ||
              t.slug.includes(query.toLowerCase())
          )
          .slice(0, 8)
      : [];

  const favoriteTools = favorites
    .map((f) => tools.find((t) => t.slug === f.tool_slug))
    .filter((t): t is Tool => Boolean(t));

  function goToTool(slug: string) {
    setSearchOpen(false);
    setQuery("");
    router.push(`/tools/${slug}`);
  }

  return (
    <header className="flex h-16 items-center gap-4 border-b border-base-border px-6">
      <div ref={searchRef} className="relative flex-1 max-w-md">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted" />
        <input
          type="text"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setSearchOpen(true);
          }}
          onFocus={() => setSearchOpen(true)}
          placeholder={t("topbar.search_placeholder")}
          className="w-full rounded-lg border border-base-border bg-base-elevated py-2 pl-9 pr-9 text-sm text-ink placeholder:text-ink-muted focus:border-signal/50"
        />
        {query && (
          <button
            type="button"
            onClick={() => setQuery("")}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-ink-muted hover:text-ink"
          >
            <X className="h-4 w-4" />
          </button>
        )}

        {searchOpen && matches.length > 0 && (
          <div className="absolute left-0 right-0 top-full z-20 mt-1 max-h-80 overflow-y-auto rounded-lg border border-base-border bg-base-elevated shadow-card">
            {matches.map((tool) => (
              <button
                key={tool.slug}
                type="button"
                onClick={() => goToTool(tool.slug)}
                className="block w-full border-b border-base-border/60 px-3 py-2 text-left last:border-0 hover:bg-base-border/40"
              >
                <p className="text-sm text-ink">{t(`tools.${tool.slug}.name` as TranslationKey)}</p>
                <p className="truncate text-xs text-ink-muted">{t(`tools.${tool.slug}.description` as TranslationKey)}</p>
              </button>
            ))}
          </div>
        )}
        {searchOpen && query.trim().length > 0 && matches.length === 0 && (
          <div className="absolute left-0 right-0 top-full z-20 mt-1 rounded-lg border border-base-border bg-base-elevated p-3 text-sm text-ink-muted shadow-card">
            {t("topbar.no_results")}
          </div>
        )}
      </div>

      <div className="ml-auto flex items-center gap-3">
        <WebCliManager />
        <button
          type="button"
          onClick={() => setLanguage(language === "de" ? "en" : "de")}
          title={language === "de" ? "Switch to English" : "Auf Deutsch umschalten"}
          className="flex items-center gap-1.5 rounded-lg border border-base-border px-2.5 py-2 text-xs font-medium uppercase text-ink-muted hover:text-ink"
        >
          <Languages className="h-4 w-4" />
          {language}
        </button>
        <div ref={favoritesRef} className="relative">
          <button
            type="button"
            onClick={() => {
              setFavoritesOpen((v) => !v);
              refreshFavorites();
            }}
            className="flex items-center gap-2 rounded-lg border border-base-border px-3 py-2 text-sm text-ink-muted hover:text-ink"
          >
            <Star className="h-4 w-4" />
            {t("topbar.favorites")}
          </button>

          {favoritesOpen && (
            <div className="absolute right-0 top-full z-20 mt-1 w-72 rounded-lg border border-base-border bg-base-elevated shadow-card">
              {favoriteTools.length === 0 ? (
                <p className="p-3 text-sm text-ink-muted">{t("topbar.no_favorites")}</p>
              ) : (
                favoriteTools.map((tool) => (
                  <div
                    key={tool.slug}
                    className="flex items-center justify-between border-b border-base-border/60 px-3 py-2 last:border-0"
                  >
                    <Link
                      href={`/tools/${tool.slug}`}
                      onClick={() => setFavoritesOpen(false)}
                      className="text-sm text-ink hover:text-signal"
                    >
                      {t(`tools.${tool.slug}.name` as TranslationKey)}
                    </Link>
                    <button
                      type="button"
                      onClick={() => toggleFavorite(tool.slug, true)}
                      title="Entfernen"
                      className="text-ink-muted hover:text-critical"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))
              )}
            </div>
          )}
        </div>

        {me && (
          <div className="flex items-center gap-3 border-l border-base-border pl-3">
            <span className="flex items-center gap-1.5 text-sm text-ink-muted">
              <StyledUsername
                username={me.username}
                role={me.role}
                isPremium={me.is_premium}
                displayNameStyle={me.display_name_style}
                displayNameColor={me.display_name_color}
                displayNameGradientColor={me.display_name_gradient_color}
                premiumBadgeColor={me.premium_badge_color}
              />
            </span>
            <button
              type="button"
              onClick={handleLogout}
              title={t("topbar.logout")}
              className="flex items-center gap-1.5 rounded-lg border border-base-border px-2.5 py-2 text-sm text-ink-muted hover:border-critical/40 hover:text-critical"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
