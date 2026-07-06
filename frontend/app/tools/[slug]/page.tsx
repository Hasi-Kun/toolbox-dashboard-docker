"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, ShieldAlert, Star } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { ToolRunner } from "@/components/tool-runner";
import { TOOL_FORMS } from "@/lib/tool-forms";
import { useLanguage } from "@/components/language-provider";
import type { TranslationKey } from "@/lib/i18n";

type ToolMeta = {
  slug: string;
  category: string;
  name: string;
  description: string;
  is_active_scan: boolean;
};

export default function ToolPage() {
  const params = useParams<{ slug: string }>();
  const { t } = useLanguage();
  const [tool, setTool] = useState<ToolMeta | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [isFavorite, setIsFavorite] = useState(false);

  useEffect(() => {
    fetch("/api/tools")
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then((all: ToolMeta[]) => {
        const found = all.find((t) => t.slug === params.slug);
        if (found) setTool(found);
        else setNotFound(true);
      })
      .catch(() => setNotFound(true));

    fetch("/api/account/favorites")
      .then((res) => (res.ok ? res.json() : []))
      .then((favs: { tool_slug: string }[]) => setIsFavorite(favs.some((f) => f.tool_slug === params.slug)))
      .catch(() => {});
  }, [params.slug]);

  async function toggleFavorite() {
    if (isFavorite) {
      await fetch(`/api/account/favorites/${params.slug}`, { method: "DELETE" });
    } else {
      await fetch("/api/account/favorites", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tool_slug: params.slug }),
      });
    }
    setIsFavorite((v) => !v);
  }

  const fields = TOOL_FORMS[params.slug];

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-4xl flex-1 overflow-y-auto p-6">
          {tool && (
            <Link
              href={`/category/${tool.category}`}
              className="mb-4 flex items-center gap-1.5 text-sm text-ink-muted hover:text-ink"
            >
              <ArrowLeft className="h-4 w-4" /> Zurueck zu {tool.category}
            </Link>
          )}

          {notFound && (
            <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              Tool &quot;{params.slug}&quot; wurde nicht gefunden.
            </p>
          )}

          {tool && (
            <>
              <div className="flex items-center justify-between">
                <h1 className="font-display text-2xl text-ink">{t(`tools.${tool.slug}.name` as TranslationKey)}</h1>
                <div className="flex items-center gap-2">
                  {tool.is_active_scan && (
                    <span className="flex items-center gap-1 rounded-full bg-warn/10 px-2 py-1 text-xs text-warn">
                      <ShieldAlert className="h-3 w-3" /> Aktiver Scan
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={toggleFavorite}
                    title={isFavorite ? "Aus Favoriten entfernen" : "Zu Favoriten hinzufuegen"}
                    className="rounded-lg border border-base-border p-2 text-ink-muted hover:border-signal/40 hover:text-signal"
                  >
                    <Star className={`h-4 w-4 ${isFavorite ? "fill-signal text-signal" : ""}`} />
                  </button>
                </div>
              </div>
              <p className="mt-1 text-sm text-ink-muted">{t(`tools.${tool.slug}.description` as TranslationKey)}</p>

              <div className="mt-6">
                {fields ? (
                  <ToolRunner slug={tool.slug} fields={fields} />
                ) : (
                  <p className="rounded-lg border border-base-border bg-base-elevated px-4 py-3 text-sm text-ink-muted">
                    Fuer dieses Tool gibt es noch kein Formular. Es ist aber schon ueber die API nutzbar:{" "}
                    <code className="font-mono text-xs">POST /api/v1/tools/{tool.slug}</code>
                  </p>
                )}
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
