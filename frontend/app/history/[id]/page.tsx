"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, CheckCircle2, XCircle } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { JsonResult } from "@/components/json-result";

type ExecutionDetail = {
  id: number;
  tool_slug: string;
  success: boolean;
  ran_at: string;
  input: Record<string, unknown> | null;
  output: Record<string, unknown> | null;
  error_message: string | null;
};

type Tool = { slug: string; name: string };

export default function HistoryDetailPage() {
  const params = useParams<{ id: string }>();
  const [execution, setExecution] = useState<ExecutionDetail | null>(null);
  const [toolName, setToolName] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    fetch(`/api/account/history/${params.id}`)
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then(setExecution)
      .catch(() => setNotFound(true));

    fetch("/api/tools")
      .then((res) => (res.ok ? res.json() : []))
      .then((tools: Tool[]) => {
        const found = tools.find((t) => t.slug === execution?.tool_slug);
        if (found) setToolName(found.name);
      })
      .catch(() => {});
  }, [params.id, execution?.tool_slug]);

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-2xl flex-1 overflow-y-auto p-6">
          <Link href="/" className="mb-4 flex items-center gap-1.5 text-sm text-ink-muted hover:text-ink">
            <ArrowLeft className="h-4 w-4" /> Zurueck zum Dashboard
          </Link>

          {notFound && (
            <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              Eintrag nicht gefunden.
            </p>
          )}

          {execution && (
            <>
              <div className="flex items-center gap-2">
                {execution.success ? (
                  <CheckCircle2 className="h-5 w-5 text-signal" />
                ) : (
                  <XCircle className="h-5 w-5 text-critical" />
                )}
                <h1 className="font-display text-2xl text-ink">{toolName ?? execution.tool_slug}</h1>
              </div>
              <p className="mt-1 text-sm text-ink-muted">
                Ausgefuehrt am {new Date(execution.ran_at + "Z").toLocaleString("de-DE")}
              </p>

              {execution.error_message && (
                <p className="mt-4 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
                  {execution.error_message}
                </p>
              )}

              {execution.input && (
                <div className="mt-6 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
                  <h3 className="mb-4 font-display text-sm text-ink-muted">Eingabe</h3>
                  <JsonResult data={execution.input} />
                </div>
              )}

              {execution.output && (
                <div className="mt-4 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
                  <h3 className="mb-4 font-display text-sm text-ink-muted">Ergebnis</h3>
                  <JsonResult data={execution.output} />
                </div>
              )}

              <Link
                href={`/tools/${execution.tool_slug}`}
                className="mt-6 inline-block rounded-lg border border-base-border px-4 py-2 text-sm text-ink-muted hover:border-signal/40 hover:text-signal"
              >
                Erneut ausfuehren
              </Link>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
