"use client";

import { useRef, useState } from "react";
import { ClipboardPaste, FileUp, Loader2, ShieldCheck } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";

const MODES: { value: string; label: string; hint: string }[] = [
  { value: "x509", label: "X.509-Zertifikat", hint: ".pem/.crt/.cer/.der -- ein einzelnes Zertifikat" },
  { value: "pkcs7", label: "PKCS#7 / S-MIME (.p7s)", hint: "Signatur-Block aus einer signierten E-Mail" },
  { value: "csr", label: "Certificate Signing Request", hint: ".csr -- ein Zertifikatsantrag" },
];

export default function OpensslFileInspectorPage() {
  const [mode, setMode] = useState("pkcs7");
  const [inputMode, setInputMode] = useState<"file" | "paste">("file");
  const [file, setFile] = useState<File | null>(null);
  const [pastedText, setPastedText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ success: boolean; output: string | null; error: string | null } | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  async function handleSubmit() {
    if (inputMode === "file" && !file) return;
    if (inputMode === "paste" && !pastedText.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const formData = new FormData();
      formData.append("mode", mode);
      if (inputMode === "file" && file) {
        formData.append("file", file);
      } else {
        formData.append("text_content", pastedText);
      }
      const res = await fetch("/api/openssl-inspect", { method: "POST", body: formData });
      const data = await res.json();
      setResult(data);
    } catch {
      setResult({ success: false, output: null, error: "Anfrage fehlgeschlagen" });
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
    }
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-2xl flex-1 overflow-y-auto p-6">
          <h1 className="font-display text-2xl text-ink">OpenSSL Datei-Inspektor</h1>
          <p className="mt-1 text-sm text-ink-muted">
            Datei hochladen ODER Text/Base64 einfuegen (Zertifikat, PKCS#7/S-MIME-Signaturblock oder CSR)
            -- wird nur im Arbeitsspeicher analysiert und direkt danach geloescht, kein dauerhafter Speicher.
          </p>

          <div className="mt-6 space-y-4 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              {MODES.map((m) => (
                <button
                  key={m.value}
                  type="button"
                  onClick={() => setMode(m.value)}
                  className={`rounded-lg border p-3 text-left transition-colors ${
                    mode === m.value ? "border-signal/50 bg-signal/10" : "border-base-border hover:border-signal/30"
                  }`}
                >
                  <p className="text-sm font-medium text-ink">{m.label}</p>
                  <p className="mt-0.5 text-xs text-ink-muted">{m.hint}</p>
                </button>
              ))}
            </div>

            <div className="flex gap-2 border-b border-base-border pb-3">
              <button
                type="button"
                onClick={() => setInputMode("file")}
                className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs ${
                  inputMode === "file" ? "bg-signal/10 text-signal" : "text-ink-muted hover:text-ink"
                }`}
              >
                <FileUp className="h-3.5 w-3.5" /> Datei hochladen
              </button>
              <button
                type="button"
                onClick={() => setInputMode("paste")}
                className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs ${
                  inputMode === "paste" ? "bg-signal/10 text-signal" : "text-ink-muted hover:text-ink"
                }`}
              >
                <ClipboardPaste className="h-3.5 w-3.5" /> Text/Base64 einfuegen
              </button>
            </div>

            {inputMode === "file" ? (
              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => inputRef.current?.click()}
                className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed p-8 text-center transition-colors ${
                  dragOver ? "border-signal bg-signal/5" : "border-base-border hover:border-signal/40"
                }`}
              >
                <FileUp className="h-6 w-6 text-ink-muted" />
                <p className="mt-2 text-sm text-ink">
                  {file ? file.name : "Datei hierher ziehen oder klicken"}
                </p>
                {file && <p className="mt-1 text-xs text-ink-muted">{(file.size / 1024).toFixed(1)} KB</p>}
                <input
                  ref={inputRef}
                  type="file"
                  className="hidden"
                  onChange={(e) => { setFile(e.target.files?.[0] ?? null); setResult(null); }}
                />
              </div>
            ) : (
              <textarea
                value={pastedText}
                onChange={(e) => { setPastedText(e.target.value); setResult(null); }}
                placeholder={"-----BEGIN CERTIFICATE-----\n...oder reines Base64 ohne PEM-Markierungen..."}
                rows={8}
                className="input font-mono text-xs"
              />
            )}

            <button
              type="button"
              onClick={handleSubmit}
              disabled={(inputMode === "file" ? !file : !pastedText.trim()) || loading}
              className="submit-button w-auto px-4"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
              Analysieren
            </button>
          </div>

          {result && (
            <div className="mt-4 rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
              {result.success ? (
                <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap font-mono text-xs text-ink">
                  {result.output}
                </pre>
              ) : (
                <p className="text-sm text-critical">{result.error}</p>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

