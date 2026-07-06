"use client";

import { useEffect, useState } from "react";
import { KeyRound, Plus, RotateCcw, ShieldOff, Trash2 } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { useIsAdmin, AdminOnlyNotice } from "@/components/use-is-admin";
import { PremiumBadge } from "@/components/premium-badge";

type UserRow = {
  id: number;
  username: string;
  role: string;
  is_active: boolean;
  has_2fa: boolean;
  invite_quota: number;
  is_premium: boolean;
  premium_badge_color: string;
};

export default function UsersSettingsPage() {
  const { isAdmin, loaded } = useIsAdmin();
  const [users, setUsers] = useState<UserRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [newUsername, setNewUsername] = useState("");
  const [newRole, setNewRole] = useState<"member" | "admin">("member");
  const [newPassword, setNewPassword] = useState("");
  const [generatedPassword, setGeneratedPassword] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  async function loadUsers() {
    const res = await fetch("/api/users");
    if (res.status === 403) {
      setError("Nur fuer Administratoren.");
      return;
    }
    if (!res.ok) {
      setError("Benutzer konnten nicht geladen werden.");
      return;
    }
    setUsers(await res.json());
  }

  useEffect(() => {
    loadUsers();
  }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    setError(null);
    setNotice(null);
    setGeneratedPassword(null);
    try {
      const res = await fetch("/api/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: newUsername,
          role: newRole,
          password: newPassword.trim() ? newPassword : undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? "Anlegen fehlgeschlagen");
      setGeneratedPassword(data.generated_password);
      if (!data.generated_password) {
        setError(null);
        setNotice(`Benutzer '${newUsername}' mit dem angegebenen Passwort angelegt.`);
      }
      setNewUsername("");
      setNewPassword("");
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Anlegen fehlgeschlagen");
    } finally {
      setCreating(false);
    }
  }

  async function handleToggleActive(user: UserRow) {
    await fetch(`/api/users/${user.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ is_active: !user.is_active }),
    });
    await loadUsers();
  }

  async function handleDelete(user: UserRow) {
    if (!confirm(`Benutzer '${user.username}' wirklich loeschen?`)) return;
    await fetch(`/api/users/${user.id}`, { method: "DELETE" });
    await loadUsers();
  }

  async function handleResetTwoFactor(user: UserRow) {
    if (!confirm(`2FA fuer '${user.username}' zuruecksetzen? Die Person muss sich neu einrichten.`)) return;
    await fetch(`/api/users/${user.id}/reset-2fa`, { method: "POST" });
    await loadUsers();
  }

  async function handleSetInviteQuota(user: UserRow, newQuota: number) {
    if (Number.isNaN(newQuota) || newQuota < 0 || newQuota > 1000) return;
    await fetch(`/api/users/${user.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ invite_quota: newQuota }),
    });
    await loadUsers();
  }

  async function handleTogglePremium(user: UserRow) {
    await fetch(`/api/users/${user.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ is_premium: !user.is_premium }),
    });
    await loadUsers();
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="flex-1 overflow-y-auto p-6">
          <h1 className="font-display text-2xl text-ink">Benutzerverwaltung</h1>
          <p className="mt-1 text-sm text-ink-muted">
            Neue Benutzer anlegen, Rollen aendern, 2FA zuruecksetzen. Es gibt keine
            oeffentliche Registrierung -- alle Accounts werden hier oder per CLI angelegt.
          </p>

          {loaded && !isAdmin && <AdminOnlyNotice />}

          {isAdmin && (
            <>
          {error && (
            <p className="mt-4 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              {error}
            </p>
          )}
          {notice && (
            <p className="mt-4 rounded-lg border border-signal/30 bg-signal/10 px-3 py-2 text-sm text-ink">
              {notice}
            </p>
          )}

          <form
            onSubmit={handleCreate}
            className="mt-6 flex flex-wrap items-end gap-3 rounded-xl border border-base-border bg-base-elevated p-4 shadow-card"
          >
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-ink-muted">Benutzername</span>
              <input
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                required
                className="input w-48"
              />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-ink-muted">Rolle</span>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as "member" | "admin")}
                className="input w-40"
              >
                <option value="member">member</option>
                <option value="admin">admin</option>
              </select>
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-ink-muted">
                Passwort (optional, sonst automatisch generiert)
              </span>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="mind. 12 Zeichen"
                minLength={12}
                className="input w-56"
              />
            </label>
            <button type="submit" disabled={creating} className="submit-button w-auto px-4">
              <Plus className="h-4 w-4" /> Benutzer anlegen
            </button>
          </form>

          {generatedPassword && (
            <p className="mt-3 rounded-lg border border-signal/30 bg-signal/10 px-3 py-2 text-sm text-ink">
              Einmal-Passwort (jetzt sicher weitergeben, wird nicht erneut angezeigt):{" "}
              <span className="font-mono text-signal">{generatedPassword}</span>
            </p>
          )}

          <div className="mt-6 overflow-hidden rounded-xl border border-base-border">
            <table className="w-full text-sm">
              <thead className="bg-base-elevated text-left text-xs uppercase tracking-wider text-ink-muted">
                <tr>
                  <th className="px-4 py-3">Benutzername</th>
                  <th className="px-4 py-3">Rolle</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">2FA</th>
                  <th className="px-4 py-3">Invite-Kontingent</th>
                  <th className="px-4 py-3">Premium</th>
                  <th className="px-4 py-3 text-right">Aktionen</th>
                </tr>
              </thead>
              <tbody>
                {users?.map((user) => (
                  <tr key={user.id} className="border-t border-base-border">
                    <td className="px-4 py-3 text-ink">
                      <span className="flex items-center gap-1.5">
                        {user.username}
                        {user.is_premium && <PremiumBadge color={user.premium_badge_color} />}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-ink-muted">{user.role}</td>
                    <td className="px-4 py-3">
                      <span className={user.is_active ? "text-signal" : "text-ink-muted"}>
                        {user.is_active ? "Aktiv" : "Deaktiviert"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={user.has_2fa ? "text-signal" : "text-warn"}>
                        {user.has_2fa ? "Eingerichtet" : "Ausstehend"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <input
                        type="number"
                        min={0}
                        max={1000}
                        defaultValue={user.invite_quota}
                        onBlur={(e) => {
                          const value = Number(e.target.value);
                          if (value !== user.invite_quota) handleSetInviteQuota(user, value);
                        }}
                        className="input w-16 py-1 text-center text-xs"
                        title="Anzahl der Einladungscodes, die dieser Nutzer selbst erstellen darf"
                      />
                    </td>
                    <td className="px-4 py-3">
                      <button
                        type="button"
                        onClick={() => handleTogglePremium(user)}
                        className={`rounded-full px-2 py-0.5 text-xs ${user.is_premium ? "bg-signal/10 text-signal" : "bg-base-border text-ink-muted"}`}
                      >
                        {user.is_premium ? "Aktiv" : "Inaktiv"}
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-2">
                        <IconButton title="2FA zuruecksetzen" onClick={() => handleResetTwoFactor(user)}>
                          <KeyRound className="h-4 w-4" />
                        </IconButton>
                        <IconButton title={user.is_active ? "Deaktivieren" : "Aktivieren"} onClick={() => handleToggleActive(user)}>
                          {user.is_active ? <ShieldOff className="h-4 w-4" /> : <RotateCcw className="h-4 w-4" />}
                        </IconButton>
                        <IconButton title="Loeschen" danger onClick={() => handleDelete(user)}>
                          <Trash2 className="h-4 w-4" />
                        </IconButton>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}

function IconButton({
  children,
  title,
  onClick,
  danger,
}: {
  children: React.ReactNode;
  title: string;
  onClick: () => void;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      className={`rounded-lg border border-base-border p-1.5 text-ink-muted hover:text-ink ${
        danger ? "hover:border-critical/40 hover:text-critical" : "hover:border-signal/40"
      }`}
    >
      {children}
    </button>
  );
}
