"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, ChevronLeft, ChevronRight, Search, XCircle } from "lucide-react";
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

type PaginatedResponse = {
  items: AuditEntry[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
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
  const [data, setData] = useState<PaginatedResponse | null>(null);
  const [eventTypes, setEventTypes] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const [page, setPage] = useState(1);

  useEffect(() => {
    fetch("/api/system/audit-log/event-types")
      .then((res) => (res.ok ? res.json() : []))
      .then(setEventTypes)
      .catch(() => setEventTypes([]));
  }, []);

  useEffect(() => {
    const params = new URLSearchParams({ page: String(page), page_size: "100" });
    if (search) params.set("search", search);
    if (eventTypeFilter) params.set("event_type", eventTypeFilter);
    fetch(`/api/system/audit-log?${params.toString()}`)
      .then((res) => (res.ok ? res.json() : null))
      .then(setData)
      .catch(() => setData(null));
  }, [search, eventTypeFilter, page]);

  useEffect(() => {
    setPage(1);
  }, [search, eventTypeFilter]);

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-5xl flex-1 overflow-y-auto p-6">
          <h1 className="font-display text-2xl text-ink">Audit-Log</h1>
          <p className="mt-1 text-sm text-ink-muted">
            Login-Versuche (erfolgreich/fehlgeschlagen) und administrative Aktionen.
          </p>

          {loaded && !isAdmin && <AdminOnlyNotice />}

          {isAdmin && (
            <>
              <div className="mt-6 flex flex-wrap items-center gap-3">
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    setSearch(searchInput);
                  }}
                  className="relative flex-1 min-w-[200px]"
                >
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted" />
                  <input
                    value={searchInput}
                    onChange={(e) => setSearchInput(e.target.value)}
                    placeholder="Suche nach Benutzer oder Detail..."
                    className="input pl-9"
                  />
                </form>
                <select
                  value={eventTypeFilter}
                  onChange={(e) => setEventTypeFilter(e.target.value)}
                  className="input w-auto"
                >
                  <option value="">Alle Ereignistypen</option>
                  {eventTypes.map((et) => (
                    <option key={et} value={et}>
                      {EVENT_LABELS[et] ?? et}
                    </option>
                  ))}
                </select>
              </div>

              {/* Dynamische/scrollbare Tabellenbreite statt fixer Spalten --
                  bei langen Detail-Texten wird der Block breiter statt
                  unleserlich umzubrechen, mit horizontalem Scroll als Fallback. */}
              <div className="mt-4 overflow-x-auto rounded-xl border border-base-border">
                <table className="w-full min-w-[900px] text-sm">
                  <thead className="bg-base-elevated text-left text-xs uppercase tracking-wider text-ink-muted">
                    <tr>
                      <th className="whitespace-nowrap px-4 py-3">Zeit</th>
                      <th className="whitespace-nowrap px-4 py-3">Ereignis</th>
                      <th className="whitespace-nowrap px-4 py-3">Benutzer</th>
                      <th className="whitespace-nowrap px-4 py-3">IP</th>
                      <th className="whitespace-nowrap px-4 py-3">Status</th>
                      <th className="px-4 py-3">Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data?.items.map((entry) => (
                      <tr key={entry.id} className="border-t border-base-border">
                        <td className="whitespace-nowrap px-4 py-3 text-xs text-ink-muted">
                          {new Date(entry.created_at + "Z").toLocaleString("de-DE")}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 text-ink">{EVENT_LABELS[entry.event_type] ?? entry.event_type}</td>
                        <td className="whitespace-nowrap px-4 py-3 text-ink-muted">{entry.username ?? "—"}</td>
                        <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-ink-muted">{entry.ip_address ?? "—"}</td>
                        <td className="whitespace-nowrap px-4 py-3">
                          {entry.success ? (
                            <CheckCircle2 className="h-4 w-4 text-signal" />
                          ) : (
                            <XCircle className="h-4 w-4 text-critical" />
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-ink-muted">{entry.detail ?? "—"}</td>
                      </tr>
                    ))}
                    {data?.items.length === 0 && (
                      <tr>
                        <td colSpan={6} className="px-4 py-6 text-center text-sm text-ink-muted">
                          Keine Eintraege gefunden.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {data && data.total_pages > 1 && (
                <div className="mt-4 flex items-center justify-between text-sm text-ink-muted">
                  <button
                    type="button"
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={data.page <= 1}
                    className="flex items-center gap-1 rounded-lg border border-base-border px-3 py-1.5 disabled:opacity-40"
                  >
                    <ChevronLeft className="h-4 w-4" /> Zurueck
                  </button>
                  <span>
                    Seite {data.page} von {data.total_pages} ({data.total} gesamt, 100 pro Seite)
                  </span>
                  <button
                    type="button"
                    onClick={() => setPage((p) => Math.min(data.total_pages, p + 1))}
                    disabled={data.page >= data.total_pages}
                    className="flex items-center gap-1 rounded-lg border border-base-border px-3 py-1.5 disabled:opacity-40"
                  >
                    Weiter <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
