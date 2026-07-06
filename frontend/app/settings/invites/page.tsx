"use client";

import { useEffect, useState } from "react";
import { Copy, Plus, Trash2 } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { useMe } from "@/components/use-is-admin";

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
  const isAdmin = me?.role === "admin";
  const canCreate = isAdmin || (me?.invite_quota ?? 0) > 0;

  const [invites, setInvites] = useState<Invite[] | null>(null);
  const [note, setNote] = useState("");
  const [role, setRole] = useState<"member" | "admin">("member");
  const [expiresInDays, setExpiresInDays] = useState(7);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<number | null>(null);

  function load() {
    // Admins sehen ALLE Invites, Member mit Invite-Recht nur ihre eigenen
    const url = isAdmin ? "/api/invites" : "/api/invites/mine";
    fetch(url)
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then(setInvites)
      .catch(() => setError("Einladungscodes konnten nicht geladen werden."));
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
      setError(data.detail ?? "Fehler beim Erstellen");
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
    const url = `${window.location.origin}/register`;
    navigator.clipboard.writeText(`${url} -- Code: ${invite.code}`);
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
            <h1 className="font-display text-2xl text-ink">Einladungscodes</h1>
            <p className="mt-4 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              Du hast noch keine Berechtigung, Einladungscodes zu erstellen. Ein Administrator kann dir
              dieses Recht unter "Benutzer" freischalten.
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
          <h1 className="font-display text-2xl text-ink">Einladungscodes</h1>
          <p className="mt-1 text-sm text-ink-muted">
            {isAdmin
              ? "Registrierung ist nur mit einem gueltigen Einladungscode moeglich."
              : "Deine eigenen Einladungscodes -- hier siehst du, wer sich mit deinem Code registriert hat."}
          </p>
          {!isAdmin && me && (
            <p className="mt-1 text-xs text-ink-muted">
              Verbleibendes Kontingent: <span className="font-mono text-signal">{me.invite_quota}</span>
            </p>
          )}

          {error && (
            <p className="mt-4 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>
          )}

          <form onSubmit={handleCreate} className="mt-4 flex flex-wrap items-end gap-3 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-ink-muted">Notiz (optional)</span>
              <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="z.B. fuer Bob" className="input w-48" />
            </label>
            {isAdmin && (
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-ink-muted">Rolle</span>
                <select value={role} onChange={(e) => setRole(e.target.value as "member" | "admin")} className="input w-32">
                  <option value="member">member</option>
                  <option value="admin">admin</option>
                </select>
              </label>
            )}
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-ink-muted">Gueltig (Tage)</span>
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
              <Plus className="h-4 w-4" /> Erstellen
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
                        verwendet von {invite.used_by_username}
                      </span>
                    ) : (
                      <span className="rounded-full bg-base-border px-1.5 py-0.5 text-[10px] text-ink-muted">offen</span>
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
                        title="Link + Code kopieren"
                        className="rounded-lg border border-base-border p-2 text-ink-muted hover:text-ink"
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </button>
                      {copiedId === invite.id && <span className="text-xs text-signal">Kopiert!</span>}
                      <button
                        type="button"
                        onClick={() => handleRevoke(invite.id)}
                        title="Widerrufen"
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
                {isAdmin ? "Noch keine Einladungscodes erstellt." : "Du hast noch keine Einladungscodes erstellt."}
              </p>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
