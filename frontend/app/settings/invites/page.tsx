"use client";

import { useEffect, useState } from "react";
import { Copy, Plus, Trash2 } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { useMe } from "@/components/use-is-admin";
import { useLanguage } from "@/components/language-provider";

type Invite = {
  id: number;
  code: string;
  note: string | null;
  role: string;
  created_at: string;
  expires_at: string | null;
  used_by_username: string | null;
  used_at: string | null;
};

export default function InvitesPage() {
  const { me, loaded } = useMe();
  const { t } = useLanguage();
  const isAdmin = me?.role === "admin";
  const canCreate = isAdmin || (me?.invite_quota ?? 0) > 0;

  const [invites, setInvites] = useState<Invite[] | null>(null);
  const [note, setNote] = useState("");
  const [role, setRole] = useState<"member" | "admin">("member");
  const [expiresInDays, setExpiresInDays] = useState(7);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<number | null>(null);

  function load() {
    const url = isAdmin ? "/api/invites" : "/api/invites/mine";
    fetch(url)
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then(setInvites)
      .catch(() => setError(t("invites.load_error")));
  }

  useEffect(() => {
    if (loaded) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loaded, isAdmin]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const res = await fetch("/api/invites", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note: note || null, role, expires_in_days: expiresInDays || null }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setError(data.detail ?? t("feature_requests.create_error"));
      return;
    }
    setNote("");
    load();
  }

  async function handleRevoke(id: number) {
    await fetch(`/api/invites/${id}`, { method: "DELETE" });
    load();
  }

  function copyLink(invite: Invite) {
    const url = `${window.location.origin}/register?code=${encodeURIComponent(invite.code)}`;
    navigator.clipboard.writeText(url);
    setCopiedId(invite.id);
    setTimeout(() => setCopiedId(null), 1500);
  }

  if (loaded && !canCreate) {
    return (
      <div className="flex min-h-screen">
        <Sidebar />
        <div className="flex flex-1 flex-col">
          <Topbar />
          <main className="mx-auto w-full max-w-2xl flex-1 overflow-y-auto p-6">
            <h1 className="font-display text-2xl text-ink">{t("invites.title")}</h1>
            <p className="mt-4 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              {t("invites.no_permission")}
            </p>
          </main>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-2xl flex-1 overflow-y-auto p-6">
          <h1 className="font-display text-2xl text-ink">{t("invites.title")}</h1>
          <p className="mt-1 text-sm text-ink-muted">
            {isAdmin ? t("invites.subtitle_admin") : t("invites.subtitle_member")}
          </p>
          {!isAdmin && me && (
            <p className="mt-1 text-xs text-ink-muted">
              {t("invites.remaining_quota")} <span className="font-mono text-signal">{me.invite_quota}</span>
            </p>
          )}

          {error && (
            <p className="mt-4 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>
          )}

          <form onSubmit={handleCreate} className="mt-4 flex flex-wrap items-end gap-3 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-ink-muted">{t("invites.note_label")}</span>
              <input value={note} onChange={(e) => setNote(e.target.value)} placeholder={t("invites.note_placeholder")} className="input w-48" />
            </label>
            {isAdmin && (
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-ink-muted">{t("invites.role_label")}</span>
                <select value={role} onChange={(e) => setRole(e.target.value as "member" | "admin")} className="input w-32">
                  <option value="member">member</option>
                  <option value="admin">admin</option>
                </select>
              </label>
            )}
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-ink-muted">{t("invites.valid_days_label")}</span>
              <input
                type="number"
                value={expiresInDays}
                onChange={(e) => setExpiresInDays(Number(e.target.value))}
                min={1}
                max={365}
                className="input w-24"
              />
            </label>
            <button type="submit" className="submit-button w-auto px-4">
              <Plus className="h-4 w-4" /> {t("common.create")}
            </button>
          </form>

          <div className="mt-6 space-y-2">
            {invites?.map((invite) => (
              <div key={invite.id} className="flex items-center justify-between rounded-lg border border-base-border bg-base-elevated p-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <code className="font-mono text-sm text-ink">{invite.code}</code>
                    <span className="rounded-full bg-base-border px-1.5 py-0.5 text-[10px] text-ink-muted">{invite.role}</span>
                    {invite.used_by_username ? (
                      <span className="rounded-full bg-signal/10 px-1.5 py-0.5 text-[10px] text-signal">
                        {t("invites.used_by")} {invite.used_by_username}
                      </span>
                    ) : (
                      <span className="rounded-full bg-base-border px-1.5 py-0.5 text-[10px] text-ink-muted">{t("invites.open_status")}</span>
                    )}
                  </div>
                  {invite.note && <p className="mt-1 text-xs text-ink-muted">{invite.note}</p>}
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  {!invite.used_by_username && (
                    <>
                      <button
                        type="button"
                        onClick={() => copyLink(invite)}
                        title={t("invites.copy_title")}
                        className="rounded-lg border border-base-border p-2 text-ink-muted hover:text-ink"
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </button>
                      {copiedId === invite.id && <span className="text-xs text-signal">{t("common.copied")}</span>}
                      <button
                        type="button"
                        onClick={() => handleRevoke(invite.id)}
                        title={t("invites.revoke_title")}
                        className="rounded-lg border border-critical/30 p-2 text-critical hover:bg-critical/10"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))}
            {invites?.length === 0 && (
              <p className="text-sm text-ink-muted">
                {isAdmin ? t("invites.no_invites_admin") : t("invites.no_invites_member")}
              </p>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
