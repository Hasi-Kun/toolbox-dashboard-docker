"use client";

import { useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, FileUp, Loader2, ShieldAlert } from "lucide-react";
import { useLanguage } from "@/components/language-provider";

type Finding = { url: string; location: string };
type ScanResult = {
  filename: string;
  file_type: string;
  suspicious: boolean;
  findings: Finding[];
  findings_truncated: boolean;
};

export default function CanaryTokenScanPage() {
  const { t } = useLanguage();
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  async function handleSubmit() {
    if (!file) return;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetch("/api/canary-token-scan", { method: "POST", body: formData });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? t("canary.request_failed"));
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("canary.request_failed"));
    } finally {
      setLoading(false);
    }
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files?.[0];
    if (dropped) {
      setFile(dropped);
      setResult(null);
      setError(null);
    }
  }

  return (
    <main className="flex-1 overflow-y-auto p-6">
      <h1 className="font-display text-2xl text-ink">{t("canary.title")}</h1>
      <p className="mt-1 text-sm text-ink-muted">{t("canary.subtitle")}</p>
      <p className="mt-2 text-xs text-ink-muted">{t("canary.note")}</p>

      <div className="mt-6 max-w-xl">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => inputRef.current?.click()}
          className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed p-8 text-center transition-colors ${
            dragOver ? "border-signal bg-signal/5" : "border-base-border bg-base-elevated"
          }`}
        >
          <FileUp className="h-8 w-8 text-ink-muted" />
          <p className="mt-2 text-sm text-ink">{file ? file.name : t("canary.drop_hint")}</p>
          <p className="mt-1 text-xs text-ink-muted">{t("canary.formats_hint")}</p>
          <input
            ref={inputRef}
            type="file"
            accept=".docx,.xlsx,.pptx,.pdf,.zip"
            className="hidden"
            onChange={(e) => {
              setFile(e.target.files?.[0] ?? null);
              setResult(null);
              setError(null);
            }}
          />
        </div>

        <button type="button" onClick={handleSubmit} disabled={!file || loading} className="submit-button mt-4">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldAlert className="h-4 w-4" />}
          {t("canary.scan_button")}
        </button>

        {error && (
          <p className="mt-4 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>
        )}

        {result && (
          <div className="mt-6 rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
            <div className="flex items-center gap-2">
              {result.suspicious ? (
                <AlertTriangle className="h-5 w-5 text-critical" />
              ) : (
                <CheckCircle2 className="h-5 w-5 text-signal" />
              )}
              <p className="font-display text-sm text-ink">
                {result.suspicious ? t("canary.result_suspicious") : t("canary.result_clean")}
              </p>
            </div>
            <p className="mt-1 font-mono text-xs text-ink-muted">
              {result.filename} ({result.file_type})
            </p>

            {result.findings.length > 0 && (
              <div className="mt-3 space-y-2">
                {result.findings.map((finding, i) => (
                  <div key={i} className="rounded-lg border border-critical/20 bg-critical/5 p-2">
                    <p data-allow-context-menu className="break-all font-mono text-xs text-ink">
                      {finding.url}
                    </p>
                    <p className="mt-0.5 text-[10px] text-ink-muted">{finding.location}</p>
                  </div>
                ))}
                {result.findings_truncated && (
                  <p className="text-xs text-ink-muted">{t("canary.findings_truncated")}</p>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </main>
  );
}
