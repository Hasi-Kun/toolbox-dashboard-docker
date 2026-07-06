"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowBigDown, ArrowBigUp, Download, MessageCircle, Plus } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { StyledUsername } from "@/components/styled-username";

type FeatureRequestSummary = {
  id: number;
  title: string;
  description: string;
  status: string;
  username: string;
  created_at: string;
  score: number;
  upvotes: number;
  downvotes: number;
  comment_count: number;
  user_vote: number;
  role: string;
  is_premium: boolean;
  premium_badge_color: string;
  display_name_style: string;
  display_name_color: string;
  display_name_gradient_color: string;
};

const STATUS_LABELS: Record<string, { label: string; className: string }> = {
  open: { label: "Offen", className: "bg-base-border text-ink-muted" },
  planned: { label: "Geplant", className: "bg-signal/10 text-signal" },
  done: { label: "Erledigt", className: "bg-signal/20 text-signal" },
  rejected: { label: "Abgelehnt", className: "bg-critical/10 text-critical" },
};

export default function FeatureRequestsPage() {
  const [requests, setRequests] = useState<FeatureRequestSummary[] | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [showArchived, setShowArchived] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function load() {
    fetch("/api/feature-requests")
      .then((res) => (res.ok ? res.json() : []))
      .then(setRequests)
      .catch(() => setRequests([]));
  }

  useEffect(load, []);

  async function handleVote(id: number, direction: "up" | "down") {
    setRequests((prev) =>
      prev
        ? prev.map((r) => {
            if (r.id !== id) return r;
            const newValue = direction === "up" ? 1 : -1;
            const wasSame = r.user_vote === newValue;
            const nextVote = wasSame ? 0 : newValue;
            return { ...r, user_vote: nextVote, score: r.score - r.user_vote + nextVote };
          })
        : prev
    );
    await fetch(`/api/feature-requests/${id}/vote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ direction }),
    });
    load();
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/feature-requests", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, description }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail ?? "Fehler beim Erstellen");
      setTitle("");
      setDescription("");
      setShowForm(false);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Fehler beim Erstellen");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-3xl flex-1 overflow-y-auto p-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="font-display text-2xl text-ink">Feature Requests</h1>
              <p className="mt-1 text-sm text-ink-muted">Vorschlaege einreichen, upvoten, kommentieren.</p>
            </div>
            <button type="button" onClick={() => setShowForm((v) => !v)} className="submit-button w-auto px-4">
              <Plus className="h-4 w-4" /> Neuer Vorschlag
            </button>
          </div>

          <a
            href="/api/feature-requests/export.csv"
            className="mt-3 inline-flex items-center gap-1.5 text-xs text-ink-muted hover:text-ink"
          >
            <Download className="h-3.5 w-3.5" /> Als CSV exportieren
          </a>

          {showForm && (
            <form onSubmit={handleSubmit} className="mt-4 space-y-3 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
              {error && <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>}
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-ink-muted">Titel</span>
                <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={150} className="input" />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-ink-muted">Beschreibung</span>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  maxLength={3000}
                  rows={4}
                  className="input"
                />
              </label>
              <button type="submit" disabled={submitting} className="submit-button w-auto px-4">
                Einreichen
              </button>
            </form>
          )}

          <div className="mt-6 space-y-3">
            {requests === null && <p className="text-sm text-ink-muted">...</p>}
            {requests?.length === 0 && <p className="text-sm text-ink-muted">Noch keine Feature-Requests.</p>}
            {(() => {
              const active = requests?.filter((r) => r.status !== "done" && r.status !== "rejected") ?? [];
              const archived = requests?.filter((r) => r.status === "done" || r.status === "rejected") ?? [];
              const visible = showArchived ? [...active, ...archived] : active;

              return (
                <>
                  {visible.map((r) => {
                    const status = STATUS_LABELS[r.status] ?? STATUS_LABELS.open;
                    return (
                      <div key={r.id} className="flex items-start gap-4 rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
                        <div className="flex shrink-0 flex-col items-center gap-0.5">
                          <button
                            type="button"
                            onClick={() => handleVote(r.id, "up")}
                            title="Upvote"
                            className={`rounded-t-lg border px-2 py-1 transition-colors ${
                              r.user_vote === 1 ? "border-signal/50 bg-signal/10 text-signal" : "border-base-border text-ink-muted hover:border-signal/30"
                            }`}
                          >
                            <ArrowBigUp className={`h-4 w-4 ${r.user_vote === 1 ? "fill-signal" : ""}`} />
                          </button>
                          <span className="text-sm font-medium text-ink">{r.score}</span>
                          <button
                            type="button"
                            onClick={() => handleVote(r.id, "down")}
                            title="Downvote"
                            className={`rounded-b-lg border px-2 py-1 transition-colors ${
                              r.user_vote === -1 ? "border-critical/50 bg-critical/10 text-critical" : "border-base-border text-ink-muted hover:border-critical/30"
                            }`}
                          >
                            <ArrowBigDown className={`h-4 w-4 ${r.user_vote === -1 ? "fill-critical" : ""}`} />
                          </button>
                        </div>

                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <Link href={`/feature-requests/${r.id}`} className="font-medium text-ink hover:text-signal">
                              {r.title}
                            </Link>
                            <span className={`rounded-full px-2 py-0.5 text-[10px] ${status.className}`}>{status.label}</span>
                          </div>
                          <p className="mt-1 line-clamp-2 text-sm text-ink-muted">{r.description}</p>
                          <div className="mt-2 flex items-center gap-3 text-xs text-ink-muted">
                            <span className="flex items-center gap-1">
                              von
                              <StyledUsername
                                username={r.username}
                                role={r.role}
                                isPremium={r.is_premium}
                                displayNameStyle={r.display_name_style}
                                displayNameColor={r.display_name_color}
                                displayNameGradientColor={r.display_name_gradient_color}
                                premiumBadgeColor={r.premium_badge_color}
                                showBadge={false}
                              />
                            </span>
                            <span>{r.upvotes} Pro / {r.downvotes} Contra</span>
                            <span className="flex items-center gap-1">
                              <MessageCircle className="h-3 w-3" /> {r.comment_count}
                            </span>
                          </div>
                        </div>
                      </div>
                    );
                  })}

                  {archived.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setShowArchived((v) => !v)}
                      className="w-full rounded-lg border border-dashed border-base-border py-2 text-xs text-ink-muted hover:text-ink"
                    >
                      {showArchived
                        ? "Erledigte/abgelehnte Vorschlaege ausblenden"
                        : `${archived.length} erledigte/abgelehnte Vorschlaege einblenden`}
                    </button>
                  )}
                </>
              );
            })()}
          </div>
        </main>
      </div>
    </div>
  );
}
