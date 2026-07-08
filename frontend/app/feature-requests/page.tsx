"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowBigDown, ArrowBigUp, ChevronLeft, ChevronRight, Download, MessageCircle, Plus, Search } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { StyledUsername } from "@/components/styled-username";
import { useLanguage } from "@/components/language-provider";

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
  tags: string[];
};

type PaginatedResponse = {
  items: FeatureRequestSummary[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
};

export default function FeatureRequestsPage() {
  const { t } = useLanguage();
  const [data, setData] = useState<PaginatedResponse | null>(null);
  const [showArchived, setShowArchived] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [newTags, setNewTags] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [activeTag, setActiveTag] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  const STATUS_LABELS: Record<string, { label: string; className: string }> = {
    open: { label: t("feature_requests.status_open"), className: "bg-base-border text-ink-muted" },
    planned: { label: t("feature_requests.status_planned"), className: "bg-signal/10 text-signal" },
    done: { label: t("feature_requests.status_done"), className: "bg-signal/20 text-signal" },
    rejected: { label: t("feature_requests.status_rejected"), className: "bg-critical/10 text-critical" },
  };

  const TAG_LABELS: Record<string, string> = {
    tools: t("feature_requests.tag_tools"),
    dashboard: t("feature_requests.tag_dashboard"),
    ui: t("feature_requests.tag_ui"),
    security: t("feature_requests.tag_security"),
    performance: t("feature_requests.tag_performance"),
    other: t("feature_requests.tag_other"),
  };
  const availableTags = Object.keys(TAG_LABELS);

  function load() {
    const params = new URLSearchParams({ page: String(page), page_size: "25" });
    if (search) params.set("search", search);
    if (activeTag) params.set("tag", activeTag);
    fetch(`/api/feature-requests?${params.toString()}`)
      .then((res) => (res.ok ? res.json() : null))
      .then(setData)
      .catch(() => setData(null));
  }

  useEffect(load, [search, activeTag, page]);

  useEffect(() => {
    setPage(1);
  }, [search, activeTag]);

  async function handleVote(id: number, direction: "up" | "down") {
    setData((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        items: prev.items.map((r) => {
          if (r.id !== id) return r;
          const newValue = direction === "up" ? 1 : -1;
          const wasSame = r.user_vote === newValue;
          const nextVote = wasSame ? 0 : newValue;
          return { ...r, user_vote: nextVote, score: r.score - r.user_vote + nextVote };
        }),
      };
    });
    await fetch(`/api/feature-requests/${id}/vote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ direction }),
    });
    load();
  }

  function toggleNewTag(tag: string) {
    setNewTags((prev) => (prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/feature-requests", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, description, tags: newTags }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail ?? t("feature_requests.create_error"));
      setTitle("");
      setDescription("");
      setNewTags([]);
      setShowForm(false);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("feature_requests.create_error"));
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
              <h1 className="font-display text-2xl text-ink">{t("feature_requests.title")}</h1>
              <p className="mt-1 text-sm text-ink-muted">{t("feature_requests.subtitle")}</p>
            </div>
            <button type="button" onClick={() => setShowForm((v) => !v)} className="submit-button w-auto px-4">
              <Plus className="h-4 w-4" /> {t("feature_requests.new_button")}
            </button>
          </div>

          <a
            href="/api/feature-requests/export.csv"
            className="mt-3 inline-flex items-center gap-1.5 text-xs text-ink-muted hover:text-ink"
          >
            <Download className="h-3.5 w-3.5" /> {t("feature_requests.export_csv")}
          </a>

          {showForm && (
            <form onSubmit={handleSubmit} className="mt-4 space-y-3 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
              {error && <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>}
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-ink-muted">{t("feature_requests.title_label")}</span>
                <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={150} className="input" />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-ink-muted">{t("feature_requests.description_label")}</span>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  maxLength={3000}
                  rows={4}
                  className="input"
                />
              </label>
              <div>
                <span className="mb-1.5 block text-xs font-medium text-ink-muted">{t("feature_requests.tags_label")}</span>
                <div className="flex flex-wrap gap-1.5">
                  {availableTags.map((tag) => (
                    <button
                      key={tag}
                      type="button"
                      onClick={() => toggleNewTag(tag)}
                      className={`rounded-full px-2.5 py-1 text-xs transition-colors ${
                        newTags.includes(tag) ? "bg-signal/15 text-signal border border-signal/40" : "bg-base-border text-ink-muted"
                      }`}
                    >
                      {TAG_LABELS[tag]}
                    </button>
                  ))}
                </div>
              </div>
              <button type="submit" disabled={submitting} className="submit-button w-auto px-4">
                {t("feature_requests.submit_button")}
              </button>
            </form>
          )}

          <div className="mt-6 flex flex-wrap items-center gap-3">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                setSearch(searchInput);
              }}
              className="relative flex-1"
            >
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted" />
              <input
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder={t("feature_requests.search_placeholder")}
                className="input pl-9"
              />
            </form>
            <div className="flex flex-wrap gap-1.5">
              <button
                type="button"
                onClick={() => setActiveTag(null)}
                className={`rounded-full px-2.5 py-1 text-xs ${!activeTag ? "bg-signal/15 text-signal border border-signal/40" : "bg-base-border text-ink-muted"}`}
              >
                {t("common.all")}
              </button>
              {availableTags.map((tag) => (
                <button
                  key={tag}
                  type="button"
                  onClick={() => setActiveTag(tag === activeTag ? null : tag)}
                  className={`rounded-full px-2.5 py-1 text-xs ${activeTag === tag ? "bg-signal/15 text-signal border border-signal/40" : "bg-base-border text-ink-muted"}`}
                >
                  {TAG_LABELS[tag]}
                </button>
              ))}
            </div>
          </div>

          <div className="mt-4 space-y-3">
            {data === null && <p className="text-sm text-ink-muted">{t("common.loading")}</p>}
            {data?.items.length === 0 && <p className="text-sm text-ink-muted">{t("feature_requests.no_results")}</p>}
            {(() => {
              const items = data?.items ?? [];
              const active = items.filter((r) => r.status !== "done" && r.status !== "rejected");
              const archived = items.filter((r) => r.status === "done" || r.status === "rejected");
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
                            title={t("feature_requests.upvote")}
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
                            title={t("feature_requests.downvote")}
                            className={`rounded-b-lg border px-2 py-1 transition-colors ${
                              r.user_vote === -1 ? "border-critical/50 bg-critical/10 text-critical" : "border-base-border text-ink-muted hover:border-critical/30"
                            }`}
                          >
                            <ArrowBigDown className={`h-4 w-4 ${r.user_vote === -1 ? "fill-critical" : ""}`} />
                          </button>
                        </div>

                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <Link href={`/feature-requests/${r.id}`} className="font-medium text-ink hover:text-signal">
                              {r.title}
                            </Link>
                            <span className={`rounded-full px-2 py-0.5 text-[10px] ${status.className}`}>{status.label}</span>
                            {r.tags.map((tag) => (
                              <span key={tag} className="rounded-full bg-base-border px-2 py-0.5 text-[10px] text-ink-muted">
                                {TAG_LABELS[tag] ?? tag}
                              </span>
                            ))}
                          </div>
                          <p className="mt-1 line-clamp-2 text-sm text-ink-muted">{r.description}</p>
                          <div className="mt-2 flex items-center gap-3 text-xs text-ink-muted">
                            <span className="flex items-center gap-1">
                              {t("feature_requests.from_label")}
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
                            <span>{r.upvotes} {t("feature_requests.pro_label")} / {r.downvotes} {t("feature_requests.contra_label")}</span>
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
                        ? t("feature_requests.archive_hide")
                        : `${archived.length} ${t("feature_requests.archive_show")}`}
                    </button>
                  )}
                </>
              );
            })()}
          </div>

          {data && data.total_pages > 1 && (
            <div className="mt-4 flex items-center justify-between text-sm text-ink-muted">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={data.page <= 1}
                className="flex items-center gap-1 rounded-lg border border-base-border px-3 py-1.5 disabled:opacity-40"
              >
                <ChevronLeft className="h-4 w-4" /> {t("common.back")}
              </button>
              <span>
                {t("common.page_of").replace("{page}", String(data.page)).replace("{total}", String(data.total_pages))}
                {" "}({data.total})
              </span>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(data.total_pages, p + 1))}
                disabled={data.page >= data.total_pages}
                className="flex items-center gap-1 rounded-lg border border-base-border px-3 py-1.5 disabled:opacity-40"
              >
                {t("common.next")} <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
