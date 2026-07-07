"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { AlertCircle } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { categories } from "@/lib/categories";
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
        if (!res.ok) throw new Error("Tools konnten nicht geladen werden");
        return res.json();
      })
      .then((all: Tool[]) => setTools(all.filter((t) => t.category === params.slug)))
      .catch((err) => setError(err instanceof Error ? err.message : "Fehler"));
  }, [params.slug]);

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="flex-1 overflow-y-auto p-6">
          <h1 className="font-display text-2xl text-ink">{categoryName}</h1>
          <p className="mt-1 text-sm text-ink-muted">{categoryDescription}</p>

          {error && (
            <p className="mt-4 flex items-center gap-2 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              <AlertCircle className="h-4 w-4" /> {error}
            </p>
          )}

          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {tools?.filter((tool) => isAdmin || !tool.requires_admin).map((tool) => (
              <Link
                key={tool.slug}
                href={`/tools/${tool.slug}`}
                className="rounded-xl border border-base-border bg-base-elevated p-5 shadow-card transition-colors hover:border-signal/40"
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="font-display text-base text-ink">{t(`tools.${tool.slug}.name` as TranslationKey)}</p>
                  <div className="flex shrink-0 gap-1.5">
                    {tool.requires_admin && (
                      <span className="rounded-full bg-signal/10 px-2 py-0.5 text-[10px] text-signal">
                        Admin
                      </span>
                    )}
                    {tool.is_active_scan && (
                      <span className="rounded-full bg-warn/10 px-2 py-0.5 text-[10px] text-warn">
                        Scan
                      </span>
                    )}
                  </div>
                </div>
                <p className="mt-1 text-sm text-ink-muted">{t(`tools.${tool.slug}.description` as TranslationKey)}</p>
                <p className="mt-3 font-mono text-xs text-ink-muted">{tool.slug}</p>
              </Link>
            ))}

            {params.slug === "certificates" && (
              <Link
                href="/tools/openssl-file-inspector"
                className="rounded-xl border border-base-border bg-base-elevated p-5 shadow-card transition-colors hover:border-signal/40"
              >
                <div className="flex items-center justify-between">
                  <p className="font-display text-base text-ink">OpenSSL Datei-Inspektor</p>
                  <span className="rounded-full bg-signal/10 px-2 py-0.5 text-[10px] text-signal">Upload</span>
                </div>
                <p className="mt-1 text-sm text-ink-muted">
                  Zertifikat, PKCS#7/S-MIME oder CSR hochladen und analysieren -- Datei wird sofort danach geloescht.
                </p>
                <p className="mt-3 font-mono text-xs text-ink-muted">openssl-file-inspector</p>
              </Link>
            )}

            {tools?.length === 0 && (
              <p className="text-sm text-ink-muted">
                Noch keine Tools in dieser Kategorie implementiert.
              </p>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
