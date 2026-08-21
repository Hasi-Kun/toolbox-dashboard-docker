"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { SystemStatusBar } from "@/components/widgets/system-status-bar";
import { RecentScansWidget } from "@/components/widgets/recent-scans-widget";
import { FavoritesWidget } from "@/components/widgets/favorites-widget";
import { ShoutboxWidget } from "@/components/widgets/shoutbox-widget";
import { categories } from "@/lib/categories";
import { categoryIconBySlug, DEFAULT_CATEGORY_ICON } from "@/lib/category-icons";
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

  return (
    <div className="flex min-h-screen">
      <Sidebar />

      <div className="flex flex-1 flex-col">
        <Topbar />

        <main className="flex-1 overflow-y-auto p-6">
          <div className="animate-stagger-in" style={{ animationDelay: "0ms" }}>
            {greeting && <p className="font-mono text-xs uppercase tracking-widest text-signal">{greeting}</p>}
            <h1 className="mt-1 font-display text-2xl text-ink">{t("dashboard.title")}</h1>
            <p className="mt-1 text-sm text-ink-muted">{t("dashboard.subtitle")}</p>
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
              <h2 className="font-display text-lg text-ink">{t("dashboard.categories")}</h2>
              <p className="mt-0.5 text-sm text-ink-muted">{t("dashboard.categories_subtitle")}</p>
            </div>
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
                  className="card-interactive group animate-stagger-in relative flex flex-col rounded-xl border border-base-border bg-base-elevated p-5 shadow-card"
                  style={{ animationDelay: `${280 + i * 45}ms` }}
                >
                  <div className="flex items-center justify-between">
                    <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-signal/10 text-signal transition-colors group-hover:bg-signal/20">
                      <Icon className="h-[18px] w-[18px]" />
                    </span>
                    <ArrowRight className="h-4 w-4 text-ink-muted opacity-0 transition-all duration-300 group-hover:translate-x-0.5 group-hover:opacity-100" />
                  </div>
                  <p className="mt-3 font-display text-base text-ink">{t(nameKey)}</p>
                  <p className="mt-1 text-sm text-ink-muted">{t(descKey)}</p>
                  <p className="mt-3 font-mono text-xs text-ink-muted">
                    {category.toolCount} {t("dashboard.tool_count_suffix")}
                  </p>
                </Link>
              );
            })}
          </div>
        </main>
      </div>
    </div>
  );
}
