"use client";

import { useEffect, useState } from "react";
import { KeyRound, Loader2, Plug, Plus, Terminal, Trash2, X } from "lucide-react";
import { useIsAdmin, AdminOnlyNotice } from "@/components/use-is-admin";
import { useLanguage } from "@/components/language-provider";
import { SshTerminal, type SshConnectParams } from "@/components/ssh/ssh-terminal";

type SavedConnection = {
  id: number;
  label: string;
  host: string;
  port: number;
  username: string;
  auth_method: "none" | "password" | "key";
  has_stored_secret: boolean;
};

export default function WebSshPage() {
  const { isAdmin, loaded } = useIsAdmin();
  const { t } = useLanguage();
  const [connections, setConnections] = useState<SavedConnection[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [activeSession, setActiveSession] = useState<{ params: SshConnectParams; title: string } | null>(null);
  const [pendingConnection, setPendingConnection] = useState<SavedConnection | null>(null);
  const [pendingSecret, setPendingSecret] = useState("");

  function loadConnections() {
    fetch("/api/ssh-connections")
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then(setConnections)
      .catch(() => setError(t("webssh.load_error")));
  }

  useEffect(() => {
    if (isAdmin) loadConnections();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  function connectSaved(conn: SavedConnection) {
    if (conn.auth_method !== "none" && !conn.has_stored_secret) {
      setPendingConnection(conn);
      return;
    }
    setActiveSession({ params: { saved_connection_id: conn.id }, title: conn.label });
  }

  function confirmPendingConnect() {
    if (!pendingConnection) return;
    setActiveSession({
      params: { saved_connection_id: pendingConnection.id, secret: pendingSecret || undefined },
      title: pendingConnection.label,
    });
    setPendingConnection(null);
    setPendingSecret("");
  }

  async function handleDelete(id: number) {
    await fetch(`/api/ssh-connections/${id}`, { method: "DELETE" });
    loadConnections();
  }

  if (!loaded) return null;
  if (!isAdmin) return <AdminOnlyNotice />;

  return (
    <main className="flex-1 overflow-y-auto p-6">
      <div className="flex items-baseline justify-between">
        <div>
          <h1 className="font-display text-2xl text-ink">{t("webssh.title")}</h1>
          <p className="mt-1 text-sm text-ink-muted">{t("webssh.subtitle")}</p>
        </div>
        <button type="button" onClick={() => setShowForm(true)} className="submit-button w-auto px-4">
          <Plus className="h-4 w-4" /> {t("webssh.new_connection")}
        </button>
      </div>

      {error && (
        <p className="mt-4 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>
      )}

      <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {connections?.map((conn) => (
          <div key={conn.id} className="card-interactive rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
            <div className="flex items-start justify-between">
              <div className="min-w-0">
                <p className="truncate font-display text-sm text-ink">{conn.label}</p>
                <p className="mt-0.5 truncate font-mono text-xs text-ink-muted">
                  {conn.username}@{conn.host}:{conn.port}
                </p>
              </div>
              <button type="button" onClick={() => handleDelete(conn.id)} className="shrink-0 text-ink-muted hover:text-critical">
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
            <button
              type="button"
              onClick={() => connectSaved(conn)}
              className="method-button mt-3 justify-center"
            >
              <Plug className="h-3.5 w-3.5" /> {t("webssh.connect")}
            </button>
          </div>
        ))}

        {connections?.length === 0 && (
          <p className="text-sm text-ink-muted">{t("webssh.no_connections")}</p>
        )}
      </div>

      {showForm && (
        <NewConnectionForm
          onClose={() => setShowForm(false)}
          onSaved={() => {
            setShowForm(false);
            loadConnections();
          }}
          onConnectAdhoc={(params, title) => {
            setShowForm(false);
            setActiveSession({ params, title });
          }}
        />
      )}

      {pendingConnection && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setPendingConnection(null)}>
          <div className="glass-card w-full max-w-sm rounded-xl bg-base-elevated p-5" onClick={(e) => e.stopPropagation()}>
            <h2 className="font-display text-base text-ink">{t("webssh.secret_needed_title")}</h2>
            <p className="mt-1 text-xs text-ink-muted">{t("webssh.secret_needed_note")}</p>
            <input
              type="password"
              autoFocus
              value={pendingSecret}
              onChange={(e) => setPendingSecret(e.target.value)}
              placeholder={pendingConnection.auth_method === "key" ? t("webssh.private_key_placeholder") : t("webssh.password_placeholder")}
              className="input mt-3"
            />
            <button type="button" onClick={confirmPendingConnect} className="submit-button mt-3">
              <Plug className="h-4 w-4" /> {t("webssh.connect")}
            </button>
          </div>
        </div>
      )}

      {activeSession && (
        <div className="fixed inset-0 z-[100] flex flex-col bg-base">
          <div className="flex items-center justify-between border-b border-base-border px-4 py-2">
            <span className="flex items-center gap-2 text-sm text-ink">
              <Terminal className="h-4 w-4 text-signal" /> {activeSession.title}
            </span>
            <button type="button" onClick={() => setActiveSession(null)} className="text-ink-muted hover:text-ink">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="flex-1 overflow-hidden">
            <SshTerminal key={activeSession.title + Date.now()} connectParams={activeSession.params} />
          </div>
        </div>
      )}
    </main>
  );
}

function NewConnectionForm({
  onClose,
  onSaved,
  onConnectAdhoc,
}: {
  onClose: () => void;
  onSaved: () => void;
  onConnectAdhoc: (params: SshConnectParams, title: string) => void;
}) {
  const { t } = useLanguage();
  const [label, setLabel] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState(22);
  const [username, setUsername] = useState("");
  const [authMethod, setAuthMethod] = useState<"none" | "password" | "key">("password");
  const [secret, setSecret] = useState("");
  const [saveForLater, setSaveForLater] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (saveForLater) {
      setSaving(true);
      try {
        const res = await fetch("/api/ssh-connections", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            label: label || `${username}@${host}`,
            host, port, username, auth_method: authMethod,
            secret: secret || null,
          }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail ?? t("webssh.save_error"));
        onSaved();
      } catch (err) {
        setError(err instanceof Error ? err.message : t("webssh.save_error"));
      } finally {
        setSaving(false);
      }
      return;
    }

    onConnectAdhoc({ host, port, username, auth_method: authMethod, secret: secret || undefined }, `${username}@${host}`);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="glass-card w-full max-w-md rounded-xl bg-base-elevated p-5" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 className="font-display text-base text-ink">{t("webssh.new_connection")}</h2>
          <button type="button" onClick={onClose} className="text-ink-muted hover:text-ink">
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="mt-4 space-y-3">
          {error && (
            <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>
          )}

          <div className="grid grid-cols-3 gap-2">
            <label className="col-span-2 block">
              <span className="mb-1 block text-xs text-ink-muted">{t("webssh.host_label")}</span>
              <input required value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.5" className="input" />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-ink-muted">{t("webssh.port_label")}</span>
              <input required type="number" value={port} onChange={(e) => setPort(Number(e.target.value))} className="input" />
            </label>
          </div>

          <label className="block">
            <span className="mb-1 block text-xs text-ink-muted">{t("webssh.username_label")}</span>
            <input required value={username} onChange={(e) => setUsername(e.target.value)} placeholder="root" className="input" />
          </label>

          <label className="block">
            <span className="mb-1 block text-xs text-ink-muted">{t("webssh.auth_method_label")}</span>
            <select value={authMethod} onChange={(e) => setAuthMethod(e.target.value as typeof authMethod)} className="input">
              <option value="password">{t("webssh.auth_password")}</option>
              <option value="key">{t("webssh.auth_key")}</option>
            </select>
          </label>

          <label className="block">
            <span className="mb-1 flex items-center gap-1.5 text-xs text-ink-muted">
              <KeyRound className="h-3 w-3" />
              {authMethod === "key" ? t("webssh.private_key_label") : t("webssh.password_label")}
            </span>
            {authMethod === "key" ? (
              <textarea
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                rows={4}
                className="input font-mono text-xs"
              />
            ) : (
              <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} className="input" />
            )}
          </label>

          <label className="flex items-center gap-2">
            <input type="checkbox" checked={saveForLater} onChange={(e) => setSaveForLater(e.target.checked)} className="h-4 w-4 rounded border-base-border accent-signal" />
            <span className="text-sm text-ink-muted">{t("webssh.save_for_later")}</span>
          </label>

          {saveForLater && (
            <label className="block">
              <span className="mb-1 block text-xs text-ink-muted">{t("webssh.label_label")}</span>
              <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder={t("webssh.label_placeholder")} className="input" />
            </label>
          )}

          <p className="text-xs text-ink-muted">{t("webssh.secret_note")}</p>

          <button type="submit" disabled={saving} className="submit-button">
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : saveForLater ? t("webssh.save_button") : <><Plug className="h-4 w-4" /> {t("webssh.connect")}</>}
          </button>
        </form>
      </div>
    </div>
  );
}
