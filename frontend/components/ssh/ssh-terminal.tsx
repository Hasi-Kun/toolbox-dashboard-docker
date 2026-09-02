"use client";

import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

export type SshConnectParams =
  | { saved_connection_id: number; secret?: string }
  | { host: string; port: number; username: string; auth_method: "password" | "key" | "none"; secret?: string };

type ConnectionState = "connecting" | "connected" | "error" | "closed";

/**
 * Interaktives SSH-Terminal ueber WebSocket + xterm.js. Die Zielangaben
 * (Host/Port/User/Credentials) kommen IMMER vom Aufrufer -- diese
 * Komponente selbst kennt keine Ziele, sie verbindet nur.
 *
 * WICHTIG: die WebSocket-Verbindung geht bewusst NICHT ueber die
 * normale /api/-BFF-Proxy-Schicht (siehe docs/CADDY.md) -- direkt zum
 * eigenen Origin unter /ws/ssh, das Caddy direkt ans Backend
 * durchreicht.
 */
export function SshTerminal({
  connectParams,
  onStateChange,
}: {
  connectParams: SshConnectParams;
  onStateChange?: (state: ConnectionState) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<ConnectionState>("connecting");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const term = new Terminal({
      fontFamily: "var(--font-mono), monospace",
      fontSize: 13,
      cursorBlink: true,
      theme: {
        background: "#0B1220",
        foreground: "#E7ECF5",
        cursor: "#35E0C0",
        selectionBackground: "#1E8F7955",
        black: "#0B1220",
        brightBlack: "#8B96AC",
        red: "#FF5C5C",
        brightRed: "#FF5C5C",
        green: "#35E0C0",
        brightGreen: "#35E0C0",
        yellow: "#F5A623",
        brightYellow: "#F5A623",
        blue: "#5B8DEF",
        brightBlue: "#5B8DEF",
        magenta: "#C792EA",
        brightMagenta: "#C792EA",
        cyan: "#35E0C0",
        brightCyan: "#35E0C0",
        white: "#E7ECF5",
        brightWhite: "#FFFFFF",
      },
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(containerRef.current);
    fitAddon.fit();

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/ssh`);

    const hadErrorRef = { current: false };

    function updateState(next: ConnectionState) {
      if (next === "error") hadErrorRef.current = true;
      setState(next);
      onStateChange?.(next);
    }

    ws.onopen = () => {
      ws.send(JSON.stringify(connectParams));
    };

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === "connected") {
        updateState("connected");
        term.focus();
      } else if (msg.type === "data") {
        term.write(msg.data);
      } else if (msg.type === "error") {
        setErrorMessage(msg.message);
        updateState("error");
        term.writeln(`\r\n\x1b[31m${msg.message}\x1b[0m`);
      }
    };

    ws.onclose = () => {
      if (!hadErrorRef.current) updateState("closed");
      term.writeln("\r\n\x1b[90m-- Verbindung getrennt --\x1b[0m");
    };

    ws.onerror = () => {
      updateState("error");
    };

    const dataDisposable = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "input", data }));
      }
    });

    const resizeObserver = new ResizeObserver(() => {
      fitAddon.fit();
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    });
    resizeObserver.observe(containerRef.current);

    return () => {
      resizeObserver.disconnect();
      dataDisposable.dispose();
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close();
      }
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="relative h-full w-full">
      {state === "connecting" && (
        <div className="absolute inset-0 z-10 flex items-center justify-center bg-base/80 text-sm text-ink-muted">
          Verbindung wird aufgebaut...
        </div>
      )}
      {state === "error" && errorMessage && (
        <div className="absolute left-0 right-0 top-0 z-10 border-b border-critical/30 bg-critical/10 px-3 py-1.5 text-xs text-critical">
          {errorMessage}
        </div>
      )}
      <div ref={containerRef} data-allow-context-menu className="h-full w-full p-2" />
    </div>
  );
}
