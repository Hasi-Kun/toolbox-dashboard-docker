"use client";

import Link from "next/link";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { StatusCard } from "@/components/widgets/status-card";
import { SystemWidgets } from "@/components/widgets/system-widgets";
import { RecentScansWidget } from "@/components/widgets/recent-scans-widget";
import { FavoritesWidget } from "@/components/widgets/favorites-widget";
import { categories } from "@/lib/categories";
import { useLanguage } from "@/components/language-provider";
import type { TranslationKey } from "@/lib/i18n";

export default function DashboardPage() {
  const { t } = useLanguage();

  return (
    <div className="flex min-h-screen">
      <Sidebar />

      <div className="flex flex-1 flex-col">
        <Topbar />

        <main className="flex-1 overflow-y-auto p-6">
          <h1 className="font-display text-2xl text-ink">{t("dashboard.title")}</h1>
          <p className="mt-1 text-sm text-ink-muted">{t("dashboard.subtitle")}</p>

          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatusCard status="online" label={t("dashboard.server_status")} />
            <SystemWidgets />
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
            <RecentScansWidget />
            <FavoritesWidget />
          </div>

          <h2 className="mt-8 font-display text-lg text-ink">{t("dashboard.categories")}</h2>
          <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {categories.map((category) => {
              const nameKey = `categories.${category.slug}.name` as TranslationKey;
              const descKey = `categories.${category.slug}.description` as TranslationKey;
              return (
                <Link
                  key={category.slug}
                  href={`/category/${category.slug}`}
                  className="rounded-xl border border-base-border bg-base-elevated p-5 shadow-card transition-colors hover:border-signal/40"
                >
                  <p className="font-display text-base text-ink">{t(nameKey)}</p>
                  <p className="mt-1 text-sm text-ink-muted">{t(descKey)}</p>
                  <p className="mt-3 font-mono text-xs text-ink-muted">
                    {category.toolCount} Tools
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
