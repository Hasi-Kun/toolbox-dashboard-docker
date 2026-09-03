"use client";

import { useState } from "react";
import { Check, ChevronRight, Copy, Terminal, X } from "lucide-react";
import { cheatsheetCategories } from "@/lib/cheatsheets";
import { TOOL_CHEATSHEET_MAP } from "@/lib/tool-cheatsheet-map";
import { useLanguage } from "@/components/language-provider";

/**
 * Einklappbares Cheatsheet-Panel fuer Tool-Seiten -- zeigt die zum
 * jeweiligen Tool passenden Cheatsheet-Eintraege (siehe
 * tool-cheatsheet-map.ts) direkt am Rand, damit man sie nebenbei
 * einsehen kann, ohne die eigentliche Tool-Seite zu verlassen.
 * Ergaenzt die vollstaendige Uebersicht unter /cheatsheets, ersetzt
 * sie nicht.
 *
 * Gibt null zurueck (rendert nichts), wenn fuer das Tool kein
 * passender Cheatsheet-Eintrag existiert -- die Seite bleibt dann
 * unveraendert wie vorher.
 */
export function CheatsheetSidePanel({ toolSlug }: { toolSlug: string }) {
  const { t } = useLanguage();
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const mapping = TOOL_CHEATSHEET_MAP[toolSlug];
  if (!mapping || mapping.length === 0) return null;

  const entries = mapping
    .map(([categorySlug, toolCheatSlug]) => {
      const category = cheatsheetCategories.find((c) => c.slug === categorySlug);
      return category?.tools.find((t) => t.slug === toolCheatSlug);
    })
    .filter((e): e is NonNullable<typeof e> => e !== undefined);

  if (entries.length === 0) return null;

  async function handleCopy(command: string) {
    await navigator.clipboard.writeText(command);
    setCopied(command);
    setTimeout(() => setCopied(null), 1500);
  }

  return (
    <>
      {/* Einklapp-Reiter -- am rechten Bildschirmrand fixiert, damit er
          auf jeder Scroll-Position der Tool-Seite erreichbar bleibt. */}
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={`fixed right-0 top-1/2 z-40 flex -translate-y-1/2 items-center gap-1.5 rounded-l-lg border border-r-0 border-base-border bg-base-elevated px-2 py-3 text-xs text-ink-muted shadow-card transition-opacity hover:text-signal ${
          open ? "pointer-events-none opacity-0" : "opacity-100"
        }`}
      >
        <Terminal className="h-4 w-4" />
        <span className="[writing-mode:vertical-rl]">{t("cheatsheets.panel_tab")}</span>
      </button>

      {/* Panel selbst */}
      <div
        className={`fixed right-0 top-0 z-50 h-full w-full max-w-sm border-l border-base-border bg-base-elevated shadow-card transition-transform duration-200 ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <div className="flex items-center justify-between border-b border-base-border p-4">
          <span className="flex items-center gap-2 font-display text-sm text-ink">
            <Terminal className="h-4 w-4 text-signal" /> {t("cheatsheets.panel_title")}
          </span>
          <button type="button" onClick={() => setOpen(false)} className="text-ink-muted hover:text-ink">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="h-[calc(100%-57px)] overflow-y-auto p-4">
          {entries.map((entry) => (
            <div key={entry.slug} className="mb-5">
              <p className="font-display text-sm text-ink">{entry.name}</p>
              <p className="mt-0.5 text-xs text-ink-muted">{entry.tagline}</p>
              <div className="mt-2 space-y-1.5">
                {entry.examples.map((ex, i) => (
                  <div key={i} className="group rounded-lg border border-base-border bg-base p-2">
                    <div className="flex items-start justify-between gap-2">
                      <code data-allow-context-menu className="min-w-0 flex-1 break-all font-mono text-xs text-signal">
                        {ex.command}
                      </code>
                      <button
                        type="button"
                        onClick={() => handleCopy(ex.command)}
                        className="shrink-0 text-ink-muted hover:text-ink"
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

          <a href="/cheatsheets" className="mt-2 flex items-center gap-1 text-xs text-signal hover:underline">
            {t("cheatsheets.panel_view_all")} <ChevronRight className="h-3 w-3" />
          </a>
        </div>
      </div>
    </>
  );
}
