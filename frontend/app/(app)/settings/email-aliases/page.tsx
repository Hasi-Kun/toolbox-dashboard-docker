"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Check, Copy, Mail, Plus, Power, Trash2 } from "lucide-react";
import { useIsAdmin, AdminOnlyNotice } from "@/components/use-is-admin";
import { useLanguage } from "@/components/language-provider";

type Alias = {
  id: number;
  address: string;
  target_email: string;
  label: string | null;
  enabled: boolean;
  forward_count: number;
};

export default function EmailAliasesPage() {
  const { isAdmin, loaded } = useIsAdmin();
  const { t } = useLanguage();
  const [domains, setDomains] = useState<string[]>([]);
  const [aliases, setAliases] = useState<Alias[] | null>(null);
  const [domain, setDomain] = useState("");
  const [localPart, setLocalPart] = useState("");
  const [targetEmail, setTargetEmail] = useState("");
  const [label, setLabel] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<number | null>(null);

  function load() {
    fetch("/api/email-aliases/domains")
      .then((res) => (res.ok ? res.json() : { domains: [] }))
      .then((data) => {
        setDomains(data.domains);
        if (data.domains.length > 0) setDomain((prev) => prev || data.domains[0]);
      });
    fetch("/api/email-aliases")
      .then((res) => (res.ok ? res.json() : []))
      .then(setAliases)
      .catch(() => setAliases([]));
  }

  useEffect(() => {
    if (isAdmin) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    setError(null);
    try {
      const res = await fetch("/api/email-aliases", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, target_email: targetEmail, local_part: localPart || null, label: label || null }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? t("aliases.create_error"));
      setLocalPart("");
      setLabel("");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("aliases.create_error"));
    } finally {
      setCreating(false);
    }
  }

  async function handleToggle(alias: Alias) {
    await fetch(`/api/email-aliases/${alias.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !alias.enabled }),
    });
    load();
  }

  async function handleDelete(id: number) {
    await fetch(`/api/email-aliases/${id}`, { method: "DELETE" });
    load();
  }

  async function handleCopy(alias: Alias) {
    await navigator.clipboard.writeText(alias.address);
    setCopiedId(alias.id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  if (!loaded) return null;
  if (!isAdmin) return <AdminOnlyNotice />;

  return (
    <main className="flex-1 overflow-y-auto p-6">
      <h1 className="font-display text-2xl text-ink">{t("aliases.title")}</h1>
      <p className="mt-1 text-sm text-ink-muted">{t("aliases.subtitle")}</p>

      {domains.length === 0 ? (
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-warn/30 bg-warn/10 px-3 py-2 text-sm text-warn">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{t("aliases.no_domains_configured")}</span>
        </div>
      ) : (
        <p className="mt-2 text-xs text-ink-muted">{t("aliases.infra_note")}</p>
      )}

      {domains.length > 0 && (
        <form onSubmit={handleCreate} className="mt-6 max-w-lg space-y-3 rounded-xl border border-base-border bg-base-elevated p-4 shadow-card">
          <div className="grid grid-cols-2 gap-2">
            <label className="block">
              <span className="mb-1 block text-xs text-ink-muted">{t("aliases.local_part_label")}</span>
              <input value={localPart} onChange={(e) => setLocalPart(e.target.value)} placeholder={t("aliases.local_part_placeholder")} className="input font-mono text-sm" />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-ink-muted">{t("aliases.domain_label")}</span>
              <select value={domain} onChange={(e) => setDomain(e.target.value)} className="input">
                {domains.map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <label className="block">
            <span className="mb-1 block text-xs text-ink-muted">{t("aliases.target_label")}</span>
            <input required type="email" value={targetEmail} onChange={(e) => setTargetEmail(e.target.value)} placeholder="echte@adresse.de" className="input" />
          </label>

          <label className="block">
            <span className="mb-1 block text-xs text-ink-muted">{t("aliases.label_label")}</span>
            <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder={t("aliases.label_placeholder")} className="input" />
          </label>

          {error && <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>}

          <button type="submit" disabled={creating} className="submit-button">
            <Plus className="h-4 w-4" /> {t("aliases.create_button")}
          </button>
        </form>
      )}

      <div className="mt-6 space-y-2">
        {aliases?.map((alias) => (
          <div key={alias.id} className="flex items-center justify-between rounded-lg border border-base-border bg-base-elevated p-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <Mail className={`h-3.5 w-3.5 ${alias.enabled ? "text-signal" : "text-ink-muted"}`} />
                <span data-allow-context-menu className="truncate font-mono text-sm text-ink">
                  {alias.address}
                </span>
              </div>
              <p className="mt-0.5 truncate text-xs text-ink-muted">
                {alias.label ? `${alias.label} -- ` : ""}
                {t("aliases.forwards_to")} {alias.target_email}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-1">
              <button type="button" onClick={() => handleCopy(alias)} title={t("aliases.copy_button")} className="text-ink-muted hover:text-ink">
                {copiedId === alias.id ? <Check className="h-4 w-4 text-signal" /> : <Copy className="h-4 w-4" />}
              </button>
              <button type="button" onClick={() => handleToggle(alias)} title={alias.enabled ? t("aliases.disable_button") : t("aliases.enable_button")} className={alias.enabled ? "text-signal" : "text-ink-muted"}>
                <Power className="h-4 w-4" />
              </button>
              <button type="button" onClick={() => handleDelete(alias.id)} className="text-ink-muted hover:text-critical">
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          </div>
        ))}
        {aliases?.length === 0 && <p className="text-sm text-ink-muted">{t("aliases.no_aliases")}</p>}
      </div>
    </main>
  );
}
