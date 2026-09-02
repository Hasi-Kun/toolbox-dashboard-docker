"use client";

import { useState } from "react";
import { Check, Copy, Loader2, Plus, Send, Trash2 } from "lucide-react";
import { useLanguage } from "@/components/language-provider";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const;
type Method = (typeof METHODS)[number];

// Vorschlaege fuer die Header-Namen-Autovervollstaendigung (datalist) --
// die gaengigsten HTTP-Header, damit man nicht jedes Mal den exakten
// Namen auswendig tippen muss.
const COMMON_HEADER_NAMES = [
  "Content-Type", "Authorization", "Accept", "Accept-Language", "User-Agent",
  "X-Forwarded-For", "X-Requested-With", "Cache-Control", "Cookie", "Referer",
  "Origin", "If-None-Match", "If-Modified-Since", "X-API-Key",
];

const COMMON_CONTENT_TYPES = [
  "application/json", "application/x-www-form-urlencoded", "text/plain", "application/xml", "multipart/form-data",
];

type HeaderRow = { key: string; value: string };
type Result = {
  status_code: number | null;
  response_headers: Record<string, string>;
  response_body: string;
  body_truncated: boolean;
  elapsed_ms: number;
  curl_command: string;
  error: string | null;
};

export default function CurlBrowserPage() {
  const { t } = useLanguage();
  const [method, setMethod] = useState<Method>("GET");
  const [url, setUrl] = useState("");
  const [headers, setHeaders] = useState<HeaderRow[]>([{ key: "", value: "" }]);
  const [body, setBody] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);

  const supportsBody = method !== "GET" && method !== "HEAD";

  function updateHeader(i: number, field: "key" | "value", value: string) {
    setHeaders((prev) => prev.map((h, idx) => (idx === i ? { ...h, [field]: value } : h)));
  }

  function addHeaderRow() {
    setHeaders((prev) => [...prev, { key: "", value: "" }]);
  }

  function removeHeaderRow(i: number) {
    setHeaders((prev) => prev.filter((_, idx) => idx !== i));
  }

  async function handleSend() {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/tools/curl-browser", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          method,
          url,
          headers: headers.filter((h) => h.key.trim()).map((h) => ({ key: h.key.trim(), value: h.value })),
          body: supportsBody && body ? body : null,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(Array.isArray(data.detail) ? data.detail.map((d: { message: string }) => d.message).join(", ") : data.detail ?? t("curl.request_failed"));
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("curl.request_failed"));
    } finally {
      setLoading(false);
    }
  }

  async function handleCopyCurl() {
    if (!result) return;
    await navigator.clipboard.writeText(result.curl_command);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  }

  return (
    <main className="flex-1 overflow-y-auto p-6">
      <h1 className="font-display text-2xl text-ink">{t("curl.title")}</h1>
      <p className="mt-1 text-sm text-ink-muted">{t("curl.subtitle")}</p>

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* --- Anfrage zusammenstellen --- */}
        <div className="space-y-4">
          <div>
            <span className="mb-1.5 block text-xs text-ink-muted">{t("curl.method_label")}</span>
            <div className="flex flex-wrap gap-1.5">
              {METHODS.map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setMethod(m)}
                  className={`rounded-lg border px-3 py-1.5 font-mono text-xs transition-colors ${
                    method === m ? "border-signal bg-signal/15 text-signal" : "border-base-border text-ink-muted hover:text-ink"
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>

          <label className="block">
            <span className="mb-1.5 block text-xs text-ink-muted">{t("curl.url_label")}</span>
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/api" className="input font-mono text-sm" />
          </label>

          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-xs text-ink-muted">{t("curl.headers_label")}</span>
              <button type="button" onClick={addHeaderRow} className="flex items-center gap-1 text-xs text-signal hover:underline">
                <Plus className="h-3 w-3" /> {t("curl.add_header")}
              </button>
            </div>
            <datalist id="header-name-suggestions">
              {COMMON_HEADER_NAMES.map((name) => (
                <option key={name} value={name} />
              ))}
            </datalist>
            <datalist id="content-type-suggestions">
              {COMMON_CONTENT_TYPES.map((ct) => (
                <option key={ct} value={ct} />
              ))}
            </datalist>
            <div className="space-y-1.5">
              {headers.map((h, i) => (
                <div key={i} className="flex gap-1.5">
                  <input
                    list="header-name-suggestions"
                    value={h.key}
                    onChange={(e) => updateHeader(i, "key", e.target.value)}
                    placeholder={t("curl.header_key_placeholder")}
                    className="input flex-1 font-mono text-xs"
                  />
                  <input
                    list={h.key.toLowerCase() === "content-type" ? "content-type-suggestions" : undefined}
                    value={h.value}
                    onChange={(e) => updateHeader(i, "value", e.target.value)}
                    placeholder={t("curl.header_value_placeholder")}
                    className="input flex-1 font-mono text-xs"
                  />
                  <button type="button" onClick={() => removeHeaderRow(i)} className="shrink-0 text-ink-muted hover:text-critical">
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {supportsBody && (
            <label className="block">
              <span className="mb-1.5 block text-xs text-ink-muted">{t("curl.body_label")}</span>
              <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={6} placeholder="{}" className="input font-mono text-xs" />
            </label>
          )}

          {error && <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>}

          <button type="button" onClick={handleSend} disabled={loading || !url.trim()} className="submit-button">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            {t("curl.send_button")}
          </button>
        </div>

        {/* --- Ergebnis --- */}
        <div className="space-y-3">
          {result && (
            <>
              <div className="rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-ink-muted">{t("curl.equivalent_curl")}</span>
                  <button type="button" onClick={handleCopyCurl} className="text-ink-muted hover:text-ink">
                    {copiedCurl ? <Check className="h-3.5 w-3.5 text-signal" /> : <Copy className="h-3.5 w-3.5" />}
                  </button>
                </div>
                <pre data-allow-context-menu className="mt-2 overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs text-signal">
                  {result.curl_command}
                </pre>
              </div>

              {result.error ? (
                <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{result.error}</p>
              ) : (
                <>
                  <div className="rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
                    <div className="flex items-center gap-3 text-sm">
                      <span className={result.status_code && result.status_code < 400 ? "text-signal" : "text-critical"}>
                        {result.status_code}
                      </span>
                      <span className="text-ink-muted">{result.elapsed_ms} ms</span>
                    </div>
                    <div className="mt-2 max-h-32 overflow-y-auto font-mono text-xs text-ink-muted">
                      {Object.entries(result.response_headers).map(([k, v]) => (
                        <p key={k} data-allow-context-menu className="break-all">
                          <span className="text-ink">{k}:</span> {v}
                        </p>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
                    <p className="text-xs text-ink-muted">{t("curl.response_body")}</p>
                    <pre data-allow-context-menu className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-ink">
                      {result.response_body || t("curl.empty_body")}
                    </pre>
                    {result.body_truncated && <p className="mt-2 text-xs text-warn">{t("curl.body_truncated")}</p>}
                  </div>
                </>
              )}
            </>
          )}
        </div>
      </div>
    </main>
  );
}
