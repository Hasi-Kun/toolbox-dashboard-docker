"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, LayoutGrid } from "lucide-react";
import { SystemStatusBar } from "@/components/widgets/system-status-bar";
import { RecentScansWidget } from "@/components/widgets/recent-scans-widget";
import { FavoritesWidget } from "@/components/widgets/favorites-widget";
import { ShoutboxWidget } from "@/components/widgets/shoutbox-widget";
import { categories } from "@/lib/categories";
import { categoryIconBySlug, DEFAULT_CATEGORY_ICON } from "@/lib/category-icons";
import { useCategoryToolCounts } from "@/lib/use-category-tool-counts";
import { useLanguage } from "@/components/language-provider";
import type { TranslationKey } from "@/lib/i18n";

function useGreeting(t: (key: TranslationKey) => string): string {
  const [greeting, setGreeting] = useState("");

  useEffect(() => {
    const hour = new Date().getHours();
    if (hour >= 5 && hour < 12) setGreeting(t("dashboard.greeting_morning"));
    else if (hour >= 12 && hour < 18) setGreeting(t("dashboard.greeting_afternoon"));
    else if (hour >= 18 && hour < 23) setGreeting(t("dashboard.greeting_evening"));
    else setGreeting(t("dashboard.greeting_night"));
  }, [t]);

  return greeting;
}

export default function DashboardPage() {
  const { t } = useLanguage();
  const greeting = useGreeting(t);
  const toolCounts = useCategoryToolCounts();
  const totalTools = Object.values(toolCounts).reduce((sum, n) => sum + n, 0);

  return (
    <main className="flex-1 overflow-y-auto p-6">
      <div className="animate-stagger-in" style={{ animationDelay: "0ms" }}>
        <div className="flex items-center gap-2">
          {greeting && <p className="font-mono text-xs uppercase tracking-widest text-signal">{greeting}</p>}
          <span className="h-px flex-1 bg-gradient-to-r from-signal/30 to-transparent" />
        </div>
        <h1 className="mt-1 font-display text-3xl tracking-tight text-ink">{t("dashboard.title")}</h1>
        <p className="mt-1.5 text-sm text-ink-muted">{t("dashboard.subtitle")}</p>
      </div>

      <div className="mt-6">
        <SystemStatusBar />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <RecentScansWidget />
        <FavoritesWidget />
        <ShoutboxWidget />
      </div>

      <div className="mt-10 flex items-baseline justify-between">
        <div>
          <h2 className="flex items-center gap-2 font-display text-lg text-ink">
            <LayoutGrid className="h-4 w-4 text-signal" />
            {t("dashboard.categories")}
          </h2>
          <p className="mt-0.5 text-sm text-ink-muted">{t("dashboard.categories_subtitle")}</p>
        </div>
        {totalTools > 0 && (
          <span className="font-mono text-xs text-ink-muted">
            {totalTools} {t("dashboard.tool_count_suffix")}
          </span>
        )}
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {categories.map((category, i) => {
          const nameKey = `categories.${category.slug}.name` as TranslationKey;
          const descKey = `categories.${category.slug}.description` as TranslationKey;
          const Icon = categoryIconBySlug[category.slug] ?? DEFAULT_CATEGORY_ICON;
          return (
            <Link
              key={category.slug}
              href={`/category/${category.slug}`}
              className="card-interactive group animate-stagger-in relative flex flex-col overflow-hidden rounded-xl border border-base-border bg-base-elevated p-5 shadow-card"
              style={{ animationDelay: `${280 + i * 45}ms` }}
            >
              {/* Dezenter Glanz-Verlauf oben rechts -- nur bei Hover sichtbar,
                  verstaerkt die Tiefenwirkung ohne aufdringlich zu sein. */}
              <span className="pointer-events-none absolute -right-8 -top-8 h-24 w-24 rounded-full bg-signal/0 blur-2xl transition-colors duration-300 group-hover:bg-signal/10" />

              <div className="flex items-center justify-between">
                <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-signal/10 text-signal ring-1 ring-inset ring-signal/10 transition-colors group-hover:bg-signal/20">
                  <Icon className="h-[19px] w-[19px]" />
                </span>
                <span className="rounded-full bg-base px-2 py-0.5 font-mono text-[11px] text-ink-muted">
                  {toolCounts[category.slug] ?? category.toolCount}
                </span>
              </div>
              <p className="mt-3.5 font-display text-base text-ink">{t(nameKey)}</p>
              <p className="mt-1 text-sm text-ink-muted">{t(descKey)}</p>
              <div className="mt-3.5 flex items-center gap-1 text-xs text-signal opacity-0 transition-opacity duration-300 group-hover:opacity-100">
                {t("dashboard.explore_category")} <ArrowRight className="h-3 w-3" />
              </div>
            </Link>
          );
        })}
      </div>
    </main>
  );
}
