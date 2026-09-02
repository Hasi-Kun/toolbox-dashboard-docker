"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import { AlertTriangle, Check, Copy, Eye, Radar } from "lucide-react";
import { useLanguage } from "@/components/language-provider";

/**
 * Oeffentliche Ansichtsseite fuer OneTimePassword-Links -- BEWUSST
 * ausserhalb der (app)-Route-Gruppe (kein Login noetig, kein Sidebar/
 * Topbar-Chrome, das einen nicht-Toolbox-Nutzer nur verwirren wuerde).
 *
 * WICHTIG: ruft das Geheimnis NICHT automatisch beim Laden ab, nur nach
 * explizitem Klick -- sonst wuerden automatische Link-Vorschauen (z.B.
 * Slack/Teams-Bots, die eine URL beim Teilen selbst kurz aufrufen) das
 * Einmal-Geheimnis vorzeitig "verbrennen", bevor der eigentliche
 * Empfaenger es je sieht.
 */
export default function ViewSecretPage() {
  const params = useParams<{ token: string }>();
  const { t } = useLanguage();
  const [state, setState] = useState<"idle" | "loading" | "revealed" | "error">("idle");
  const [content, setContent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function handleReveal() {
    setState("loading");
    try {
      const res = await fetch(`/api/one-time-secrets/${params.token}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? t("ots_view.error_generic"));
      setContent(data.content);
      setState("revealed");
    } catch (err) {
      setError(err instanceof Error ? err.message : t("ots_view.error_generic"));
      setState("error");
    }
  }

  async function handleCopy() {
    if (!content) return;
    await navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-base p-6">
      <div className="w-full max-w-sm rounded-xl border border-base-border bg-base-elevated p-6 shadow-card">
        <div className="flex items-center gap-2">
          <Radar className="h-5 w-5 text-signal" strokeWidth={2.5} />
          <span className="font-display text-lg text-ink">toolbox</span>
        </div>

        {state === "idle" && (
          <>
            <p className="mt-4 text-sm text-ink-muted">{t("ots_view.intro")}</p>
            <p className="mt-2 text-xs text-warn">{t("ots_view.warning_once")}</p>
            <button type="button" onClick={handleReveal} className="submit-button mt-4">
              <Eye className="h-4 w-4" /> {t("ots_view.reveal_button")}
            </button>
          </>
        )}

        {state === "loading" && <p className="mt-4 text-sm text-ink-muted">{t("ots_view.loading")}</p>}

        {state === "revealed" && content && (
          <>
            <p className="mt-4 text-xs text-ink-muted">{t("ots_view.revealed_note")}</p>
            <div className="mt-2 flex items-center gap-2">
              <pre data-allow-context-menu className="max-h-64 flex-1 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-base-border bg-base p-3 font-mono text-sm text-ink">
                {content}
              </pre>
            </div>
            <button type="button" onClick={handleCopy} className="method-button mt-3 justify-center">
              {copied ? <Check className="h-4 w-4 text-signal" /> : <Copy className="h-4 w-4" />}
              {copied ? t("ots_view.copied") : t("ots_view.copy_button")}
            </button>
          </>
        )}

        {state === "error" && (
          <div className="mt-4 flex items-start gap-2 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>
    </div>
  );
}
