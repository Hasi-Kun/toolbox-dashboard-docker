"use client";

import { useEffect, useRef, useState } from "react";
import { TerminalSquare } from "lucide-react";
import { executeCommand } from "@/components/webcli/cli-commands";

type Tool = { slug: string; name: string; description: string; category: string; is_active_scan?: boolean };

export function ToolConsole({
  fixedSlug,
  allowedSlugs,
  placeholder,
  introLines,
}: {
  /** Wenn gesetzt, ist die Konsole auf GENAU dieses eine Tool eingeschraenkt --
   * der Nutzer tippt nur noch die Argumente, der Slug wird automatisch vorangestellt. */
  fixedSlug?: string;
  /** Wenn gesetzt (ohne fixedSlug), duerfen nur Befehle mit einem dieser Slugs
   * ausgefuehrt werden -- z.B. alle nmap-*-Slugs fuer eine "nmap-Konsole". */
  allowedSlugs?: string[];
  placeholder?: string;
  introLines?: string[];
}) {
  const [tools, setTools] = useState<Tool[]>([]);
  const [lines, setLines] = useState<string[]>(introLines ?? []);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/tools")
      .then((res) => (res.ok ? res.json() : []))
      .then(setTools)
      .catch(() => setTools([]));
  }, []);

  useEffect(() => {
    bodyRef.current?.scrollTo({ top: bodyRef.current.scrollHeight });
  }, [lines]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim() || busy) return;

    const trimmed = input.trim();
    const firstToken = trimmed.split(/\s+/)[0]?.toLowerCase();

    if (allowedSlugs && !fixedSlug && !["help", "clear", "list"].includes(firstToken) && !allowedSlugs.includes(firstToken)) {
      setLines((prev) => [...prev, `> ${trimmed}`, `Diese Konsole erlaubt nur: ${allowedSlugs.join(", ")}`]);
      setInput("");
      return;
    }

    const commandLine = fixedSlug ? `${fixedSlug} ${trimmed}` : trimmed;
    setBusy(true);
    setLines((prev) => [...prev, `> ${fixedSlug ? trimmed : trimmed}`]);
    try {
      const result = await executeCommand(commandLine, tools);
      if (result.clear) {
        setLines([]);
      } else {
        setLines((prev) => [...prev, ...result.lines]);
      }
    } finally {
      setInput("");
      setBusy(false);
    }
  }

  return (
    <div className="overflow-hidden rounded-xl border border-base-border bg-base shadow-card">
      <div className="flex items-center gap-2 border-b border-base-border bg-base-elevated px-3 py-2 text-xs text-ink-muted">
        <TerminalSquare className="h-3.5 w-3.5" /> Konsole
      </div>
      <div ref={bodyRef} className="max-h-72 overflow-y-auto p-3 font-mono text-xs leading-relaxed">
        {lines.length === 0 && <p className="text-ink-muted/50">Bereit. 'help' fuer Hilfe.</p>}
        {lines.map((line, i) => (
          <div
            key={i}
            className={
              line.startsWith(">") ? "text-signal" : line.startsWith("Fehler") ? "text-critical" : "text-ink"
            }
          >
            {line}
          </div>
        ))}
        {busy && <div className="text-ink-muted">laeuft...</div>}
      </div>
      <form onSubmit={handleSubmit} className="flex items-center gap-2 border-t border-base-border px-3 py-2">
        <span className="text-signal">&gt;</span>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={placeholder}
          disabled={busy}
          className="flex-1 bg-transparent font-mono text-xs text-ink outline-none placeholder:text-ink-muted/50"
          autoComplete="off"
        />
      </form>
    </div>
  );
}
