"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, XCircle } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { useIsAdmin, AdminOnlyNotice } from "@/components/use-is-admin";

type AuditEntry = {
  id: number;
  event_type: string;
  username: string | null;
  ip_address: string | null;
  success: boolean;
  detail: string | null;
  created_at: string;
};

const EVENT_LABELS: Record<string, string> = {
  login_password: "Login (Passwort)",
  login_2fa: "Login (2FA)",
  admin_create_user: "Benutzer angelegt",
  admin_update_user: "Benutzer geaendert",
  admin_delete_user: "Benutzer geloescht",
  invite_created: "Invite erstellt",
  invite_revoked: "Invite widerrufen",
};

export default function AuditLogPage() {
  const { isAdmin, loaded } = useIsAdmin();
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);

  useEffect(() => {
    fetch("/api/system/audit-log?limit=200")
      .then((res) => (res.ok ? res.json() : []))
      .then(setEntries)
      .catch(() => setEntries([]));
  }, []);

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-3xl flex-1 overflow-y-auto p-6">
          <h1 className="font-display text-2xl text-ink">Audit-Log</h1>
          <p className="mt-1 text-sm text-ink-muted">
            Login-Versuche (erfolgreich/fehlgeschlagen) und administrative Aktionen.
          </p>

          {loaded && !isAdmin && <AdminOnlyNotice />}

          {isAdmin && (
            <div className="mt-6 overflow-hidden rounded-xl border border-base-border">
              <table className="w-full text-sm">
                <thead className="bg-base-elevated text-left text-xs uppercase tracking-wider text-ink-muted">
                  <tr>
                    <th className="px-4 py-3">Zeit</th>
                    <th className="px-4 py-3">Ereignis</th>
                    <th className="px-4 py-3">Benutzer</th>
                    <th className="px-4 py-3">IP</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {entries?.map((entry) => (
                    <tr key={entry.id} className="border-t border-base-border">
                      <td className="whitespace-nowrap px-4 py-3 text-xs text-ink-muted">
                        {new Date(entry.created_at + "Z").toLocaleString("de-DE")}
                      </td>
                      <td className="px-4 py-3 text-ink">{EVENT_LABELS[entry.event_type] ?? entry.event_type}</td>
                      <td className="px-4 py-3 text-ink-muted">{entry.username ?? "—"}</td>
                      <td className="px-4 py-3 font-mono text-xs text-ink-muted">{entry.ip_address ?? "—"}</td>
                      <td className="px-4 py-3">
                        {entry.success ? (
                          <CheckCircle2 className="h-4 w-4 text-signal" />
                        ) : (
                          <XCircle className="h-4 w-4 text-critical" />
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-ink-muted">{entry.detail ?? "—"}</td>
                    </tr>
                  ))}
                  {entries?.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-6 text-center text-sm text-ink-muted">
                        Noch keine Eintraege.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
