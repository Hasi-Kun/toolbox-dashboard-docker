"use client";

import { useMemo, useState } from "react";
import { Check, Copy, Search, Terminal } from "lucide-react";
import { cheatsheetCategories } from "@/lib/cheatsheets";
import { useLanguage } from "@/components/language-provider";

export default function CheatsheetsPage() {
  const { t } = useLanguage();
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return cheatsheetCategories;

    return cheatsheetCategories
      .map((cat) => ({
        ...cat,
        tools: cat.tools.filter(
          (tool) =>
            tool.name.toLowerCase().includes(q) ||
            tool.tagline.toLowerCase().includes(q) ||
            tool.examples.some((ex) => ex.command.toLowerCase().includes(q) || ex.description.toLowerCase().includes(q))
        ),
      }))
      .filter((cat) => cat.tools.length > 0);
  }, [query]);

  async function handleCopy(command: string) {
    await navigator.clipboard.writeText(command);
    setCopied(command);
    setTimeout(() => setCopied(null), 1500);
  }

  return (
    <main className="flex-1 overflow-y-auto p-6">
      <h1 className="font-display text-2xl text-ink">{t("cheatsheets.title")}</h1>
      <p className="mt-1 text-sm text-ink-muted">{t("cheatsheets.subtitle")}</p>

      <div className="relative mt-4 max-w-md">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("cheatsheets.search_placeholder")}
          className="input pl-9"
        />
      </div>

      <div className="mt-6 space-y-8">
        {filtered.map((category) => (
          <section key={category.slug}>
            <h2 className="font-display text-lg text-ink">{category.name}</h2>
            <div className="mt-3 grid grid-cols-1 gap-4 lg:grid-cols-2">
              {category.tools.map((tool) => (
                <div key={tool.slug} className="rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
                  <div className="flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-signal" />
                    <span className="font-display text-sm text-ink">{tool.name}</span>
                  </div>
                  <p className="mt-1 text-xs text-ink-muted">{tool.tagline}</p>

                  <div className="mt-3 space-y-2">
                    {tool.examples.map((ex, i) => (
                      <div key={i} className="group rounded-lg border border-base-border bg-base p-2">
                        <div className="flex items-start justify-between gap-2">
                          <code data-allow-context-menu className="min-w-0 flex-1 break-all font-mono text-xs text-signal">
                            {ex.command}
                          </code>
                          <button
                            type="button"
                            onClick={() => handleCopy(ex.command)}
                            className="shrink-0 text-ink-muted opacity-0 transition-opacity group-hover:opacity-100 hover:text-ink"
                          >
                            {copied === ex.command ? <Check className="h-3.5 w-3.5 text-signal" /> : <Copy className="h-3.5 w-3.5" />}
                          </button>
                        </div>
                        <p className="mt-1 text-xs text-ink-muted">{ex.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </section>
        ))}

        {filtered.length === 0 && <p className="text-sm text-ink-muted">{t("cheatsheets.no_results")}</p>}
      </div>
    </main>
  );
}
