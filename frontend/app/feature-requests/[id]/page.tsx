"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { ArrowBigDown, ArrowBigUp, ArrowLeft, Trash2 } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { StyledUsername } from "@/components/styled-username";
import { useLanguage } from "@/components/language-provider";

type DisplayFields = {
  role: string;
  is_premium: boolean;
  premium_badge_color: string;
  display_name_style: string;
  display_name_color: string;
  display_name_gradient_color: string;
};

type Comment = { id: number; username: string; comment: string; created_at: string } & DisplayFields;
type Detail = {
  id: number;
  title: string;
  description: string;
  status: string;
  username: string;
  created_at: string;
  score: number;
  upvotes: number;
  downvotes: number;
  user_vote: number;
  comments: Comment[];
} & DisplayFields;
type Me = { id: number; username: string; role: string };

const STATUS_OPTIONS = ["open", "planned", "done", "rejected"];

export default function FeatureRequestDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const { t } = useLanguage();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [comment, setComment] = useState("");
  const [notFound, setNotFound] = useState(false);

  function load() {
    fetch(`/api/feature-requests/${params.id}`)
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then(setDetail)
      .catch(() => setNotFound(true));
  }

  useEffect(() => {
    fetch("/api/auth/me")
      .then((res) => (res.ok ? res.json() : null))
      .then(setMe)
      .catch(() => {});
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.id]);

  async function handleVote(direction: "up" | "down") {
    await fetch(`/api/feature-requests/${params.id}/vote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ direction }),
    });
    load();
  }

  async function handleComment(e: React.FormEvent) {
    e.preventDefault();
    if (!comment.trim()) return;
    await fetch(`/api/feature-requests/${params.id}/comments`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ comment }),
    });
    setComment("");
    load();
  }

  async function handleDeleteComment(commentId: number) {
    await fetch(`/api/feature-requests/${params.id}/comments/${commentId}`, { method: "DELETE" });
    load();
  }

  async function handleStatusChange(status: string) {
    await fetch(`/api/feature-requests/${params.id}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    load();
  }

  async function handleDeleteRequest() {
    await fetch(`/api/feature-requests/${params.id}`, { method: "DELETE" });
    router.push("/feature-requests");
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-2xl flex-1 overflow-y-auto p-6">
          <Link href="/feature-requests" className="mb-4 flex items-center gap-1.5 text-sm text-ink-muted hover:text-ink">
            <ArrowLeft className="h-4 w-4" /> {t("feature_requests.back_to_overview")}
          </Link>

          {notFound && (
            <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              {t("feature_requests.not_found")}
            </p>
          )}

          {detail && (
            <>
              <div className="flex items-start gap-4 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
                <div className="flex shrink-0 flex-col items-center gap-0.5">
                  <button
                    type="button"
                    onClick={() => handleVote("up")}
                    title={t("feature_requests.upvote")}
                    className={`rounded-t-lg border px-3 py-1.5 ${
                      detail.user_vote === 1 ? "border-signal/50 bg-signal/10 text-signal" : "border-base-border text-ink-muted hover:border-signal/30"
                    }`}
                  >
                    <ArrowBigUp className={`h-5 w-5 ${detail.user_vote === 1 ? "fill-signal" : ""}`} />
                  </button>
                  <span className="text-sm font-medium text-ink">{detail.score}</span>
                  <button
                    type="button"
                    onClick={() => handleVote("down")}
                    title={t("feature_requests.downvote")}
                    className={`rounded-b-lg border px-3 py-1.5 ${
                      detail.user_vote === -1 ? "border-critical/50 bg-critical/10 text-critical" : "border-base-border text-ink-muted hover:border-critical/30"
                    }`}
                  >
                    <ArrowBigDown className={`h-5 w-5 ${detail.user_vote === -1 ? "fill-critical" : ""}`} />
                  </button>
                </div>
                <div className="min-w-0 flex-1">
                  <h1 className="font-display text-xl text-ink">{detail.title}</h1>
                  <p className="mt-1 flex items-center gap-1 text-xs text-ink-muted">
                    {t("feature_requests.from_label")}
                    <StyledUsername
                      username={detail.username}
                      role={detail.role}
                      isPremium={detail.is_premium}
                      displayNameStyle={detail.display_name_style}
                      displayNameColor={detail.display_name_color}
                      displayNameGradientColor={detail.display_name_gradient_color}
                      premiumBadgeColor={detail.premium_badge_color}
                    />
                    &middot; {detail.upvotes} {t("feature_requests.pro_label")} / {detail.downvotes} {t("feature_requests.contra_label")}
                  </p>
                  <p className="mt-3 whitespace-pre-wrap text-sm text-ink">{detail.description}</p>
                </div>
              </div>

              {me?.role === "admin" && (
                <div className="mt-4 flex items-center justify-between rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
                  <label className="flex items-center gap-2 text-sm text-ink-muted">
                    {t("feature_requests.status_change_label")}
                    <select
                      value={detail.status}
                      onChange={(e) => handleStatusChange(e.target.value)}
                      className="input w-40"
                    >
                      {STATUS_OPTIONS.map((s) => (
                        <option key={s} value={s}>
                          {s}
                        </option>
                      ))}
                    </select>
                  </label>
                  <button
                    type="button"
                    onClick={handleDeleteRequest}
                    className="flex items-center gap-1.5 rounded-lg border border-critical/30 px-3 py-1.5 text-sm text-critical hover:bg-critical/10"
                  >
                    <Trash2 className="h-3.5 w-3.5" /> {t("common.delete")}
                  </button>
                </div>
              )}

              <h2 className="mt-6 font-display text-sm text-ink-muted">{t("feature_requests.comments_heading")}</h2>
              <div className="mt-2 space-y-2">
                {detail.comments.length === 0 && <p className="text-sm text-ink-muted">{t("feature_requests.no_comments")}</p>}
                {detail.comments.map((c) => (
                  <div key={c.id} className="group flex items-start justify-between gap-2 rounded-lg border border-base-border bg-base-elevated p-3">
                    <div>
                      <p className="text-xs font-medium text-ink">
                        <StyledUsername
                          username={c.username}
                          role={c.role}
                          isPremium={c.is_premium}
                          displayNameStyle={c.display_name_style}
                          displayNameColor={c.display_name_color}
                          displayNameGradientColor={c.display_name_gradient_color}
                          premiumBadgeColor={c.premium_badge_color}
                          showBadge={false}
                        />
                      </p>
                      <p className="mt-0.5 text-sm text-ink-muted">{c.comment}</p>
                    </div>
                    {(me?.role === "admin" || me?.username === c.username) && (
                      <button
                        type="button"
                        onClick={() => handleDeleteComment(c.id)}
                        className="shrink-0 text-ink-muted opacity-0 hover:text-critical group-hover:opacity-100"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>

              <form onSubmit={handleComment} className="mt-3 flex gap-2">
                <input
                  type="text"
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  maxLength={1000}
                  placeholder={t("feature_requests.comment_placeholder")}
                  className="input flex-1"
                />
                <button type="submit" disabled={!comment.trim()} className="submit-button w-auto px-4">
                  {t("feature_requests.comment_submit")}
                </button>
              </form>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
