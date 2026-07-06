"use client";

import { useRef, useState } from "react";
import { Minus, TerminalSquare, X } from "lucide-react";
import { executeCommand } from "@/components/webcli/cli-commands";

type Tool = { slug: string; name: string; description: string; category: string };

export interface CliWindowState {
  id: string;
  title: string;
  x: number;
  y: number;
  width: number;
  height: number;
  minimized: boolean;
  history: string[];
}

export function CliWindow({
  win,
  tools,
  onClose,
  onMinimize,
  onFocus,
  onMove,
  onResize,
  onHistoryChange,
  zIndex,
}: {
  win: CliWindowState;
  tools: Tool[];
  onClose: () => void;
  onMinimize: () => void;
  onFocus: () => void;
  onMove: (x: number, y: number) => void;
  onResize: (width: number, height: number) => void;
  onHistoryChange: (history: string[]) => void;
  zIndex: number;
}) {
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const dragRef = useRef<{ startX: number; startY: number; originX: number; originY: number } | null>(null);
  const resizeRef = useRef<{ startX: number; startY: number; originWidth: number; originHeight: number } | null>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  const MIN_WIDTH = 320;
  const MIN_HEIGHT = 220;

  function handleResizeStart(e: React.MouseEvent) {
    e.stopPropagation();
    onFocus();
    resizeRef.current = { startX: e.clientX, startY: e.clientY, originWidth: win.width, originHeight: win.height };
    window.addEventListener("mousemove", handleResizeMove);
    window.addEventListener("mouseup", handleResizeEnd);
  }

  function handleResizeMove(e: MouseEvent) {
    if (!resizeRef.current) return;
    const dx = e.clientX - resizeRef.current.startX;
    const dy = e.clientY - resizeRef.current.startY;
    onResize(
      Math.max(MIN_WIDTH, resizeRef.current.originWidth + dx),
      Math.max(MIN_HEIGHT, resizeRef.current.originHeight + dy)
    );
  }

  function handleResizeEnd() {
    resizeRef.current = null;
    window.removeEventListener("mousemove", handleResizeMove);
    window.removeEventListener("mouseup", handleResizeEnd);
  }

  function handleDragStart(e: React.MouseEvent) {
    onFocus();
    dragRef.current = { startX: e.clientX, startY: e.clientY, originX: win.x, originY: win.y };
    window.addEventListener("mousemove", handleDragMove);
    window.addEventListener("mouseup", handleDragEnd);
  }

  function handleDragMove(e: MouseEvent) {
    if (!dragRef.current) return;
    const dx = e.clientX - dragRef.current.startX;
    const dy = e.clientY - dragRef.current.startY;
    onMove(dragRef.current.originX + dx, dragRef.current.originY + dy);
  }

  function handleDragEnd() {
    dragRef.current = null;
    window.removeEventListener("mousemove", handleDragMove);
    window.removeEventListener("mouseup", handleDragEnd);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim() || busy) return;
    const command = input;
    setInput("");
    const newHistory = [...win.history, `$ ${command}`];
    onHistoryChange(newHistory);
    setBusy(true);
    const result = await executeCommand(command, tools);
    setBusy(false);
    if (result.clear) {
      onHistoryChange([]);
    } else {
      onHistoryChange([...newHistory, ...result.lines]);
    }
    setTimeout(() => bodyRef.current?.scrollTo({ top: bodyRef.current.scrollHeight }), 0);
  }

  if (win.minimized) return null;

  return (
    <div
      className="fixed flex flex-col rounded-lg border border-base-border bg-base shadow-2xl"
      style={{ left: win.x, top: win.y, width: win.width, height: win.height, zIndex }}
      onMouseDown={onFocus}
    >
      <div
        className="flex cursor-move items-center justify-between rounded-t-lg border-b border-base-border bg-base-elevated px-3 py-1.5"
        onMouseDown={handleDragStart}
      >
        <span className="flex items-center gap-1.5 text-xs font-medium text-ink-muted">
          <TerminalSquare className="h-3.5 w-3.5 text-signal" /> {win.title}
        </span>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={onMinimize}
            className="rounded p-1 text-ink-muted hover:bg-base-border hover:text-ink"
            title="Minimieren"
          >
            <Minus className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-ink-muted hover:bg-critical/20 hover:text-critical"
            title="Schliessen"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div ref={bodyRef} className="flex-1 overflow-y-auto p-3 font-mono text-xs text-ink">
        {win.history.length === 0 && (
          <p className="text-ink-muted">Toolbox WebCLI. 'help' fuer Befehle, 'list' fuer alle Tools.</p>
        )}
        {win.history.map((line, i) => (
          <div key={i} className={line.startsWith("$ ") ? "text-signal" : "whitespace-pre-wrap text-ink"}>
            {line}
          </div>
        ))}
        {busy && <div className="text-ink-muted">...</div>}
      </div>

      <form onSubmit={handleSubmit} className="flex items-center gap-2 border-t border-base-border px-3 py-2">
        <span className="font-mono text-xs text-signal">$</span>
        <input
          autoFocus
          value={input}
          onChange={(e) => setInput(e.target.value)}
          className="flex-1 bg-transparent font-mono text-xs text-ink outline-none"
          placeholder="ping example.com"
        />
      </form>

      <div
        onMouseDown={handleResizeStart}
        title="Groesse aendern"
        className="absolute bottom-0 right-0 h-4 w-4 cursor-nwse-resize"
        style={{
          background: "linear-gradient(135deg, transparent 50%, rgba(53,224,192,0.4) 50%)",
        }}
      />
    </div>
  );
}
