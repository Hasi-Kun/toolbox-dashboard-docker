"use client";

import { useEffect, useState } from "react";
import { Terminal } from "lucide-react";
import { CliWindow, type CliWindowState } from "@/components/webcli/cli-window";

type Tool = { slug: string; name: string; description: string; category: string };

let windowCounter = 0;

export function WebCliManager() {
  const [isAdmin, setIsAdmin] = useState(false);
  const [tools, setTools] = useState<Tool[]>([]);
  const [windows, setWindows] = useState<CliWindowState[]>([]);
  const [zOrder, setZOrder] = useState<string[]>([]);

  useEffect(() => {
    fetch("/api/auth/me")
      .then((res) => (res.ok ? res.json() : null))
      .then((me: { role?: string } | null) => setIsAdmin(me?.role === "admin"))
      .catch(() => setIsAdmin(false));
    fetch("/api/tools")
      .then((res) => (res.ok ? res.json() : []))
      .then(setTools)
      .catch(() => setTools([]));
  }, []);

  function openNewWindow() {
    windowCounter += 1;
    const id = `cli-${windowCounter}`;
    const offset = (windows.length % 5) * 24;
    const win: CliWindowState = {
      id,
      title: `WebCLI ${windowCounter}`,
      x: 120 + offset,
      y: 100 + offset,
      width: 480,
      height: 340,
      minimized: false,
      history: [],
    };
    setWindows((prev) => [...prev, win]);
    setZOrder((prev) => [...prev, id]);
  }

  function updateWindow(id: string, patch: Partial<CliWindowState>) {
    setWindows((prev) => prev.map((w) => (w.id === id ? { ...w, ...patch } : w)));
  }

  function closeWindow(id: string) {
    setWindows((prev) => prev.filter((w) => w.id !== id));
    setZOrder((prev) => prev.filter((z) => z !== id));
  }

  function focusWindow(id: string) {
    setZOrder((prev) => [...prev.filter((z) => z !== id), id]);
  }

  if (!isAdmin) return null;

  const minimizedWindows = windows.filter((w) => w.minimized);

  return (
    <>
      <button
        type="button"
        onClick={openNewWindow}
        title="Neues WebCLI-Fenster oeffnen"
        className="flex items-center gap-1.5 rounded-lg border border-base-border px-2.5 py-2 text-xs font-medium uppercase text-ink-muted hover:text-ink"
      >
        <Terminal className="h-4 w-4" />
      </button>

      {windows.map((win) => (
        <CliWindow
          key={win.id}
          win={win}
          tools={tools}
          zIndex={100 + zOrder.indexOf(win.id)}
          onFocus={() => focusWindow(win.id)}
          onClose={() => closeWindow(win.id)}
          onMinimize={() => updateWindow(win.id, { minimized: true })}
          onMove={(x, y) => updateWindow(win.id, { x, y })}
          onResize={(width, height) => updateWindow(win.id, { width, height })}
          onHistoryChange={(history) => updateWindow(win.id, { history })}
        />
      ))}

      {minimizedWindows.length > 0 && (
        <div className="fixed bottom-0 left-0 right-0 z-[200] flex gap-2 border-t border-base-border bg-base-elevated/95 px-4 py-2 backdrop-blur-sm">
          {minimizedWindows.map((win) => (
            <button
              key={win.id}
              type="button"
              onClick={() => {
                updateWindow(win.id, { minimized: false });
                focusWindow(win.id);
              }}
              className="flex items-center gap-1.5 rounded-lg border border-base-border bg-base px-3 py-1.5 text-xs text-ink-muted hover:text-ink"
            >
              <Terminal className="h-3.5 w-3.5 text-signal" /> {win.title}
            </button>
          ))}
        </div>
      )}
    </>
  );
}
