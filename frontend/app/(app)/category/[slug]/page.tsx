"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { AlertCircle } from "lucide-react";
import { categories } from "@/lib/categories";
import { SPECIAL_TOOLS } from "@/lib/special-tools";
import { SUBCATEGORIES } from "@/lib/subcategories";
import { useLanguage } from "@/components/language-provider";
import type { TranslationKey } from "@/lib/i18n";

type Tool = {
  slug: string;
  category: string;
  name: string;
  description: string;
  is_active_scan: boolean;
  requires_admin: boolean;
};

type DisplayTool = {
  slug: string;
  name: string;
  description: string;
  requiresAdmin: boolean;
  isActiveScan: boolean;
  isUpload: boolean;
};

export default function CategoryPage() {
  const params = useParams<{ slug: string }>();
  const { t } = useLanguage();
  const [tools, setTools] = useState<Tool[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);

  const category = categories.find((c) => c.slug === params.slug);
  const categoryName = category ? t(`categories.${category.slug}.name` as TranslationKey) : params.slug;
  const categoryDescription = category
    ? t(`categories.${category.slug}.description` as TranslationKey)
    : "Unbekannte Kategorie";

  useEffect(() => {
    fetch("/api/auth/me")
      .then((res) => (res.ok ? res.json() : null))
      .then((me: { role?: string } | null) => setIsAdmin(me?.role === "admin"))
      .catch(() => setIsAdmin(false));

    fetch("/api/tools")
      .then((res) => {
        // Frueher wurde hier bei 401 still zu /login umgeleitet -- das
        // uebernimmt jetzt zentral <SessionGuard /> im (app)-Layout, MIT
        // erklaerendem Hinweis-Popup. Hier nur noch der normale
        // Fehlerfall fuer eine tatsaechlich fehlgeschlagene Anfrage.
        if (!res.ok) throw new Error("Tools konnten nicht geladen werden");
        return res.json();
      })
      .then((all: Tool[] | null) => {
        if (all) setTools(all.filter((tool) => tool.category === params.slug));
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Fehler"));
  }, [params.slug]);

  // Registrierte Tools UND Datei-Upload-Sondertools (siehe special-tools.ts)
  // zu einer gemeinsamen Liste zusammenfuehren, damit beide gleichermassen
  // gruppiert/dargestellt werden -- vorher zwei getrennte Render-Bloecke,
  // was Unterkategorien-Gruppierung unmoeglich gemacht haette.
  const allDisplayTools: DisplayTool[] = [
    ...(tools ?? [])
      .filter((tool) => isAdmin || !tool.requires_admin)
      .map((tool) => ({
        slug: tool.slug,
        name: t(`tools.${tool.slug}.name` as TranslationKey),
        description: t(`tools.${tool.slug}.description` as TranslationKey),
        requiresAdmin: tool.requires_admin,
        isActiveScan: tool.is_active_scan,
        isUpload: false,
      })),
    ...SPECIAL_TOOLS.filter((s) => s.category === params.slug).map((special) => ({
      slug: special.slug,
      name: special.name,
      description: special.description,
      requiresAdmin: false,
      isActiveScan: false,
      isUpload: true,
    })),
  ];

  const groups = SUBCATEGORIES[params.slug];
  const byslug = new Map(allDisplayTools.map((tool) => [tool.slug, tool]));

  // Gruppierte Darstellung (Reihenfolge/Zuordnung aus subcategories.ts),
  // plus eine "Weitere"-Auffanggruppe fuer alles, was dort (noch) nicht
  // zugeordnet ist -- neue Tools verschwinden so nie unsichtbar.
  const groupedSlugs = new Set(groups?.flatMap((g) => g.tools) ?? []);
  const ungrouped = allDisplayTools.filter((tool) => !groupedSlugs.has(tool.slug));

  return (
    <main className="flex-1 overflow-y-auto p-6">
      <h1 className="font-display text-2xl text-ink">{categoryName}</h1>
      <p className="mt-1 text-sm text-ink-muted">{categoryDescription}</p>

      {error && (
        <p className="mt-4 flex items-center gap-2 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
          <AlertCircle className="h-4 w-4" /> {error}
        </p>
      )}

      {tools === null && !error && <p className="mt-6 text-sm text-ink-muted">{t("category_page.loading")}</p>}

      {tools !== null && allDisplayTools.length === 0 && (
        <p className="mt-6 text-sm text-ink-muted">{t("category_page.empty")}</p>
      )}

      <div className="mt-6 space-y-8">
        {groups?.map((group) => {
          const groupTools = group.tools.map((slug) => byslug.get(slug)).filter((t): t is DisplayTool => t !== undefined);
          if (groupTools.length === 0) return null;
          return (
            <section key={group.name}>
              <h2 className="text-xs font-medium uppercase tracking-wider text-ink-muted">{group.name}</h2>
              <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {groupTools.map((tool) => (
                  <ToolTile key={tool.slug} tool={tool} />
                ))}
              </div>
            </section>
          );
        })}

        {ungrouped.length > 0 && (
          <section>
            {groups && <h2 className="text-xs font-medium uppercase tracking-wider text-ink-muted">{t("category_page.more")}</h2>}
            <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {ungrouped.map((tool) => (
                <ToolTile key={tool.slug} tool={tool} />
              ))}
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

function ToolTile({ tool }: { tool: DisplayTool }) {
  return (
    <Link
      href={`/tools/${tool.slug}`}
      className="group rounded-lg border border-base-border bg-base-elevated p-3.5 shadow-card transition-colors hover:border-signal/40"
    >
      <div className="flex items-start justify-between gap-2">
        <p className="font-display text-sm text-ink">{tool.name}</p>
        <div className="flex shrink-0 gap-1">
          {tool.isUpload && <span className="rounded-full bg-signal/10 px-1.5 py-0.5 text-[9px] text-signal">Upload</span>}
          {tool.requiresAdmin && <span className="rounded-full bg-signal/10 px-1.5 py-0.5 text-[9px] text-signal">Admin</span>}
          {tool.isActiveScan && <span className="rounded-full bg-warn/10 px-1.5 py-0.5 text-[9px] text-warn">Scan</span>}
        </div>
      </div>
      <p className="mt-1 truncate text-xs text-ink-muted group-hover:whitespace-normal">{tool.description}</p>
    </Link>
  );
}
