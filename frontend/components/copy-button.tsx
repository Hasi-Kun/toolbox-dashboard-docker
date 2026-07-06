"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";

export function CopyButton({ text, className = "" }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy(e: React.MouseEvent) {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // Clipboard-API kann fehlschlagen (z.B. kein HTTPS) -- dann still
      // nichts tun statt einen Fehler fuer dieses Nice-to-have anzuzeigen.
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={copied ? "Kopiert!" : "Kopieren"}
      className={`inline-flex shrink-0 items-center justify-center rounded p-0.5 text-ink-muted opacity-0 transition-opacity hover:text-ink group-hover:opacity-100 ${className}`}
    >
      {copied ? <Check className="h-3 w-3 text-signal" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}
