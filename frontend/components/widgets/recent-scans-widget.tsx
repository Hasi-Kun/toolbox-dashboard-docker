"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { CheckCircle2, XCircle } from "lucide-react";
import { useLanguage } from "@/components/language-provider";
import type { TranslationKey } from "@/lib/i18n";

type Execution = { id: number; tool_slug: string; success: boolean; ran_at: string };
type Tool = { slug: string; name: string };

function timeAgo(isoString: string): string {
  const seconds = Math.floor((Date.now() - new Date(isoString + "Z").getTime()) / 1000);
  if (seconds < 60) return "gerade eben";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `vor ${minutes} Min.`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `vor ${hours} Std.`;
  return `vor ${Math.floor(hours / 24)} Tagen`;
}

export function RecentScansWidget() {
  const { t } = useLanguage();
  const [executions, setExecutions] = useState<Execution[] | null>(null);
  const [tools, setTools] = useState<Tool[]>([]);

  useEffect(() => {
    fetch("/api/tools")
      .then((res) => (res.ok ? res.json() : []))
      .then(setTools)
      .catch(() => setTools([]));

    fetch("/api/account/history?limit=8")
      .then((res) => (res.ok ? res.json() : []))
      .then(setExecutions)
      .catch(() => setExecutions([]));
  }, []);

  function toolName(slug: string): string {
    const translated = t(`tools.${slug}.name` as TranslationKey);
    return translated !== `tools.${slug}.name` ? translated : tools.find((tool) => tool.slug === slug)?.name ?? slug;
  }

  return (
    <div className="rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
      <p className="text-sm text-ink-muted">{t("dashboard.recent_scans")}</p>

      {executions === null && <p className="mt-4 text-sm text-ink-muted">...</p>}

      {executions?.length === 0 && (
        <div className="mt-4 flex h-24 items-center justify-center rounded-lg border border-dashed border-base-border text-center text-sm text-ink-muted">
          {t("dashboard.no_recent_scans")}
        </div>
      )}

      {executions && executions.length > 0 && (
        <ul className="mt-3 space-y-1.5">
          {executions.map((exec, i) => (
            <li key={i}>
              <Link
                href={`/history/${exec.id}`}
                className="flex items-center justify-between gap-2 rounded-lg px-2 py-1.5 text-sm hover:bg-base-border/40"
              >
                <span className="flex items-center gap-2 text-ink">
                  {exec.success ? (
                    <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-signal" />
                  ) : (
                    <XCircle className="h-3.5 w-3.5 shrink-0 text-critical" />
                  )}
                  {toolName(exec.tool_slug)}
                </span>
                <span className="shrink-0 text-xs text-ink-muted">{timeAgo(exec.ran_at)}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
