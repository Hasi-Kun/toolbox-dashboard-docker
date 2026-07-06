"use client";

import { useEffect, useRef, useState } from "react";
import { MessageSquare, Send, Trash2 } from "lucide-react";
import { PremiumBadge } from "@/components/premium-badge";

type Message = { id: number; username: string; message: string; created_at: string; is_own: boolean; is_premium: boolean; premium_badge_color: string };
type Me = { role: string };

function timeAgo(isoString: string): string {
  const seconds = Math.floor((Date.now() - new Date(isoString + "Z").getTime()) / 1000);
  if (seconds < 60) return "gerade eben";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `vor ${minutes} Min.`;
  const hours = Math.floor(minutes / 60);
  return `vor ${hours} Std.`;
}

export function ShoutboxWidget() {
  const [messages, setMessages] = useState<Message[] | null>(null);
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  function load() {
    fetch("/api/chat/messages?limit=50")
      .then((res) => (res.ok ? res.json() : []))
      .then(setMessages)
      .catch(() => {});
  }

  useEffect(() => {
    fetch("/api/auth/me")
      .then((res) => (res.ok ? res.json() : null))
      .then((me: Me | null) => setIsAdmin(me?.role === "admin"))
      .catch(() => {});
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight });
  }, [messages]);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    if (!text.trim()) return;
    setSending(true);
    try {
      const res = await fetch("/api/chat/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text }),
      });
      if (res.ok) {
        setText("");
        load();
      }
    } finally {
      setSending(false);
    }
  }

  async function handleDelete(id: number) {
    await fetch(`/api/chat/messages/${id}`, { method: "DELETE" });
    load();
  }

  return (
    <div className="flex h-full flex-col rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
      <div className="flex items-center gap-2 text-ink-muted">
        <MessageSquare className="h-4 w-4" />
        <span className="text-sm">Shoutbox</span>
      </div>

      <div ref={listRef} className="mt-3 flex-1 space-y-2 overflow-y-auto" style={{ maxHeight: "220px" }}>
        {messages === null && <p className="text-sm text-ink-muted">...</p>}
        {messages?.length === 0 && <p className="text-sm text-ink-muted">Noch keine Nachrichten.</p>}
        {messages?.map((m) => (
          <div key={m.id} className="group flex items-start justify-between gap-2 text-sm">
            <div className="min-w-0">
              <span className={m.is_own ? "font-medium text-signal" : "font-medium text-ink"}>{m.username}</span>
              {m.is_premium && <PremiumBadge color={m.premium_badge_color} />}
              <span className="ml-1.5 text-xs text-ink-muted">{timeAgo(m.created_at)}</span>
              <p className="break-words text-ink">{m.message}</p>
            </div>
            {isAdmin && (
              <button
                type="button"
                onClick={() => handleDelete(m.id)}
                className="shrink-0 text-ink-muted opacity-0 hover:text-critical group-hover:opacity-100"
                title="Nachricht loeschen"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        ))}
      </div>

      <form onSubmit={handleSend} className="mt-3 flex gap-2">
        <input
          type="text"
          value={text}
          onChange={(e) => setText(e.target.value)}
          maxLength={500}
          placeholder="Nachricht..."
          className="input flex-1"
        />
        <button type="submit" disabled={sending || !text.trim()} className="submit-button w-auto px-3">
          <Send className="h-4 w-4" />
        </button>
      </form>
    </div>
  );
}
