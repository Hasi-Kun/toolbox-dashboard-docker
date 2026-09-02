"use client";

import { useEffect, useState } from "react";
import { Check, Copy, KeyRound, Loader2, Plus, Trash2 } from "lucide-react";
import { useIsAdmin, AdminOnlyNotice } from "@/components/use-is-admin";
import { useLanguage } from "@/components/language-provider";

type SecretMeta = {
  token: string;
  created_at: string;
  expires_at: string;
  viewed_at: string | null;
  is_expired: boolean;
  max_views: number;
  view_count: number;
};

const TTL_OPTIONS = [
  { hours: 1, key: "1h" },
  { hours: 24, key: "1d" },
  { hours: 24 * 3, key: "3d" },
  { hours: 24 * 7, key: "7d" },
  { hours: 24 * 14, key: "14d" },
];

export default function OneTimeSecretsPage() {
  const { isAdmin, loaded } = useIsAdmin();
  const { t } = useLanguage();
  const [content, setContent] = useState("");
  const [ttlHours, setTtlHours] = useState(24);
  const [creating, setCreating] = useState(false);
  const [createdLink, setCreatedLink] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secrets, setSecrets] = useState<SecretMeta[] | null>(null);
  const [copiedToken, setCopiedToken] = useState<string | null>(null);
  const [extendToken, setExtendToken] = useState<string | null>(null);
  const [extendHours, setExtendHours] = useState(24);

  function loadSecrets() {
    fetch("/api/one-time-secrets/mine")
      .then((res) => (res.ok ? res.json() : []))
      .then(setSecrets)
      .catch(() => setSecrets([]));
  }

  useEffect(() => {
    if (isAdmin) loadSecrets();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!content.trim()) return;
    setCreating(true);
    setError(null);
    setCreatedLink(null);
    try {
      const res = await fetch("/api/one-time-secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content, ttl_hours: ttlHours }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? t("ots.create_error"));
      setCreatedLink(`${window.location.origin}/s/${data.token}`);
      setContent("");
      loadSecrets();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("ots.create_error"));
    } finally {
      setCreating(false);
    }
  }

  function linkFor(token: string) {
    return `${window.location.origin}/s/${token}`;
  }

  async function handleCopy() {
    if (!createdLink) return;
    await navigator.clipboard.writeText(createdLink);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function handleCopyRow(token: string) {
    await navigator.clipboard.writeText(linkFor(token));
    setCopiedToken(token);
    setTimeout(() => setCopiedToken(null), 2000);
  }

  async function handleAddView(token: string) {
    await fetch(`/api/one-time-secrets/mine/${token}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ add_views: 1 }),
    });
    loadSecrets();
  }

  async function handleExtend(token: string) {
    await fetch(`/api/one-time-secrets/mine/${token}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ extend_ttl_hours: extendHours }),
    });
    setExtendToken(null);
    loadSecrets();
  }

  async function handleRevoke(token: string) {
    await fetch(`/api/one-time-secrets/mine/${token}`, { method: "DELETE" });
    loadSecrets();
  }

  if (!loaded) return null;
  if (!isAdmin) return <AdminOnlyNotice />;

  return (
    <main className="flex-1 overflow-y-auto p-6">
      <h1 className="font-display text-2xl text-ink">{t("ots.title")}</h1>
      <p className="mt-1 text-sm text-ink-muted">{t("ots.subtitle")}</p>
      <p className="mt-2 text-xs text-ink-muted">{t("ots.note")}</p>

      <form onSubmit={handleCreate} className="mt-6 max-w-lg space-y-3 rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
        <label className="block">
          <span className="mb-1 block text-xs text-ink-muted">{t("ots.content_label")}</span>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            rows={3}
            placeholder={t("ots.content_placeholder")}
            className="input font-mono text-sm"
          />
        </label>

        <label className="block">
          <span className="mb-1 block text-xs text-ink-muted">{t("ots.ttl_label")}</span>
          <select value={ttlHours} onChange={(e) => setTtlHours(Number(e.target.value))} className="input">
            {TTL_OPTIONS.map((opt) => (
              <option key={opt.key} value={opt.hours}>
                {t(`ots.ttl_${opt.key}` as never)}
              </option>
            ))}
          </select>
        </label>

        {error && (
          <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>
        )}

        <button type="submit" disabled={creating || !content.trim()} className="submit-button">
          {creating ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
          {t("ots.create_button")}
        </button>
      </form>

      {createdLink && (
        <div className="mt-4 max-w-lg rounded-xl border border-signal/30 bg-signal/5 p-4">
          <p className="text-sm text-ink">{t("ots.link_ready")}</p>
          <div className="mt-2 flex items-center gap-2">
            <code data-allow-context-menu className="flex-1 truncate rounded-lg bg-base px-3 py-2 font-mono text-xs text-ink">
              {createdLink}
            </code>
            <button type="button" onClick={handleCopy} className="method-button w-auto px-3">
              {copied ? <Check className="h-4 w-4 text-signal" /> : <Copy className="h-4 w-4" />}
            </button>
          </div>
        </div>
      )}

      <h2 className="mt-8 font-display text-lg text-ink">{t("ots.my_links_title")}</h2>
      <div className="mt-3 space-y-2">
        {secrets?.map((s) => (
          <div key={s.token} className="rounded-lg border border-base-border bg-base-elevated p-3">
            <div className="flex items-center justify-between">
              <div className="min-w-0">
                <p className="truncate font-mono text-xs text-ink-muted">{s.token.slice(0, 24)}...</p>
                <p className="mt-0.5 text-xs text-ink-muted">
                  {s.is_expired ? t("ots.status_expired") : t("ots.status_active")}
                  {" -- "}
                  {t("ots.views_label")} {s.view_count}/{s.max_views}
                  {" -- "}
                  {t("ots.expires_at_label")} {new Date(s.expires_at).toLocaleString()}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-1">
                <button type="button" onClick={() => handleCopyRow(s.token)} title={t("ots.copy_link_button")} className="text-ink-muted hover:text-ink">
                  {copiedToken === s.token ? <Check className="h-4 w-4 text-signal" /> : <Copy className="h-4 w-4" />}
                </button>
                <button type="button" onClick={() => handleAddView(s.token)} title={t("ots.add_view_button")} className="text-ink-muted hover:text-ink">
                  <Plus className="h-4 w-4" />
                </button>
                <button type="button" onClick={() => setExtendToken(extendToken === s.token ? null : s.token)} className="rounded-lg border border-base-border px-2 py-1 text-xs text-ink-muted hover:text-ink">
                  {t("ots.extend_button")}
                </button>
                <button type="button" onClick={() => handleRevoke(s.token)} className="text-ink-muted hover:text-critical">
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>

            {extendToken === s.token && (
              <div className="mt-2 flex items-center gap-2 border-t border-base-border pt-2">
                <select value={extendHours} onChange={(e) => setExtendHours(Number(e.target.value))} className="input w-40 text-xs">
                  {TTL_OPTIONS.map((opt) => (
                    <option key={opt.key} value={opt.hours}>
                      {t(`ots.ttl_${opt.key}` as never)}
                    </option>
                  ))}
                </select>
                <button type="button" onClick={() => handleExtend(s.token)} className="method-button w-auto px-3 text-xs">
                  {t("ots.extend_confirm")}
                </button>
              </div>
            )}
          </div>
        ))}
        {secrets?.length === 0 && <p className="text-sm text-ink-muted">{t("ots.no_links")}</p>}
      </div>
    </main>
  );
}
