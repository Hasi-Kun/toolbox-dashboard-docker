"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, ChevronLeft, ChevronRight, Search, XCircle } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { useIsAdmin, AdminOnlyNotice } from "@/components/use-is-admin";
import { useLanguage } from "@/components/language-provider";

type ScanEntry = {
  id: number;
  tool_slug: string;
  username: string;
  target: string | null;
  success: boolean;
  ran_at: string;
  error_message: string | null;
};

type PaginatedResponse = {
  items: ScanEntry[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
};

export default function ScanHistoryPage() {
  const { isAdmin, loaded } = useIsAdmin();
  const { t } = useLanguage();
  const [data, setData] = useState<PaginatedResponse | null>(null);
  const [tools, setTools] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [toolFilter, setToolFilter] = useState("");
  const [page, setPage] = useState(1);

  useEffect(() => {
    fetch("/api/system/scan-history/tools")
      .then((res) => (res.ok ? res.json() : []))
      .then(setTools)
      .catch(() => setTools([]));
  }, []);

  useEffect(() => {
    const params = new URLSearchParams({ page: String(page), page_size: "50" });
    if (search) params.set("search", search);
    if (toolFilter) params.set("tool_slug", toolFilter);
    fetch(`/api/system/scan-history?${params.toString()}`)
      .then((res) => (res.ok ? res.json() : null))
      .then(setData)
      .catch(() => setData(null));
  }, [search, toolFilter, page]);

  useEffect(() => {
    setPage(1);
  }, [search, toolFilter]);

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-5xl flex-1 overflow-y-auto p-6">
          <h1 className="font-display text-2xl text-ink">{t("scan_history.title")}</h1>
          <p className="mt-1 text-sm text-ink-muted">{t("scan_history.subtitle")}</p>

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
                    placeholder={t("scan_history.search_placeholder")}
                    className="input pl-9"
                  />
                </form>
                <select value={toolFilter} onChange={(e) => setToolFilter(e.target.value)} className="input w-auto">
                  <option value="">{t("scan_history.all_tools")}</option>
                  {tools.map((tSlug) => (
                    <option key={tSlug} value={tSlug}>{tSlug}</option>
                  ))}
                </select>
              </div>

              <div className="mt-4 overflow-x-auto rounded-xl border border-base-border">
                <table className="w-full min-w-[800px] text-sm">
                  <thead className="bg-base-elevated text-left text-xs uppercase tracking-wider text-ink-muted">
                    <tr>
                      <th className="whitespace-nowrap px-4 py-3">{t("scan_history.col_time")}</th>
                      <th className="whitespace-nowrap px-4 py-3">{t("scan_history.col_tool")}</th>
                      <th className="whitespace-nowrap px-4 py-3">{t("scan_history.col_user")}</th>
                      <th className="whitespace-nowrap px-4 py-3">{t("scan_history.col_target")}</th>
                      <th className="whitespace-nowrap px-4 py-3">{t("scan_history.col_status")}</th>
                      <th className="px-4 py-3">{t("scan_history.col_error")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data?.items.map((entry) => (
                      <tr key={entry.id} className="border-t border-base-border">
                        <td className="whitespace-nowrap px-4 py-3 text-xs text-ink-muted">
                          {new Date(entry.ran_at + "Z").toLocaleString("de-DE")}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-ink">{entry.tool_slug}</td>
                        <td className="whitespace-nowrap px-4 py-3 text-ink-muted">{entry.username}</td>
                        <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-ink-muted">{entry.target ?? "—"}</td>
                        <td className="whitespace-nowrap px-4 py-3">
                          {entry.success ? (
                            <CheckCircle2 className="h-4 w-4 text-signal" />
                          ) : (
                            <XCircle className="h-4 w-4 text-critical" />
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-ink-muted">{entry.error_message ?? "—"}</td>
                      </tr>
                    ))}
                    {data?.items.length === 0 && (
                      <tr>
                        <td colSpan={6} className="px-4 py-6 text-center text-sm text-ink-muted">
                          {t("scan_history.no_entries")}
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
            </>
          )}
        </main>
      </div>
    </div>
  );
}
