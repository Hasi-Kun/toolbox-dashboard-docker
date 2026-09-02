"use client";

import { useEffect, useState } from "react";
import { Boxes, Loader2, RotateCw, X } from "lucide-react";
import { useLanguage } from "@/components/language-provider";

type Container = {
  name: string;
  id: string;
  image: string;
  state: string;
  status: string;
};

const STATE_COLOR: Record<string, string> = {
  running: "bg-signal",
  restarting: "bg-warn",
  paused: "bg-warn",
  exited: "bg-critical",
  dead: "bg-critical",
};

/**
 * Popup mit der eigenen Toolbox-Container-Stack (nicht fremde Container
 * auf demselben Host -- die filtert das Backend bereits raus, siehe
 * app/api/v1/endpoints/system.py TOOLBOX_CONTAINER_NAMES). Jeder
 * Container laesst sich einzeln neu starten -- die eigentliche
 * Sicherheitsgrenze (nur eigene Container, Admin-only, Audit-Log) liegt
 * im Backend, dieses Popup ist nur die Bedienoberflaeche dafuer.
 */
export function DockerStatusModal({ onClose }: { onClose: () => void }) {
  const { t } = useLanguage();
  const [containers, setContainers] = useState<Container[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [restarting, setRestarting] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);

  function load() {
    fetch("/api/system/docker")
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then((data) => setContainers(data.containers))
      .catch(() => setError(t("docker_modal.load_error")));
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleRestart(name: string) {
    setConfirming(null);
    setRestarting(name);
    setError(null);
    try {
      const res = await fetch(`/api/system/docker/${name}/restart`, { method: "POST" });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail ?? t("docker_modal.restart_error"));
      }
      // Kurze Pause -- ein frisch neugestarteter Container braucht einen
      // Moment, bevor der naechste Status-Abruf "running" zeigt.
      await new Promise((resolve) => setTimeout(resolve, 1500));
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("docker_modal.restart_error"));
    } finally {
      setRestarting(null);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
      role="presentation"
    >
      <div
        className="glass-card w-full max-w-lg rounded-xl bg-base-elevated p-5"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <div className="flex items-center justify-between">
          <h2 className="flex items-center gap-2 font-display text-base text-ink">
            <Boxes className="h-4 w-4" /> {t("docker_modal.title")}
          </h2>
          <button type="button" onClick={onClose} className="text-ink-muted hover:text-ink">
            <X className="h-4 w-4" />
          </button>
        </div>
        <p className="mt-1 text-xs text-ink-muted">{t("docker_modal.subtitle")}</p>

        {error && (
          <p className="mt-3 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
            {error}
          </p>
        )}

        <div className="mt-4 space-y-2">
          {containers === null && !error && (
            <p className="flex items-center gap-2 text-sm text-ink-muted">
              <Loader2 className="h-4 w-4 animate-spin" /> {t("docker_modal.loading")}
            </p>
          )}

          {containers?.map((c) => (
            <div
              key={c.name}
              className="flex items-center justify-between rounded-lg border border-base-border bg-base p-3"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 shrink-0 rounded-full ${STATE_COLOR[c.state] ?? "bg-ink-muted"}`} />
                  <span className="truncate font-mono text-sm text-ink">{c.name}</span>
                </div>
                <p className="mt-0.5 truncate text-xs text-ink-muted">{c.status}</p>
              </div>

              {confirming === c.name ? (
                <div className="flex shrink-0 items-center gap-1.5">
                  <span className="text-xs text-ink-muted">{t("docker_modal.confirm_question")}</span>
                  <button
                    type="button"
                    onClick={() => handleRestart(c.name)}
                    className="rounded-lg bg-critical/15 px-2 py-1 text-xs font-medium text-critical hover:bg-critical/25"
                  >
                    {t("docker_modal.confirm_yes")}
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirming(null)}
                    className="rounded-lg border border-base-border px-2 py-1 text-xs text-ink-muted hover:text-ink"
                  >
                    {t("docker_modal.confirm_no")}
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => setConfirming(c.name)}
                  disabled={restarting !== null}
                  title={t("docker_modal.restart_button")}
                  className="ml-2 shrink-0 rounded-lg border border-base-border p-1.5 text-ink-muted hover:border-signal/40 hover:text-signal disabled:opacity-50"
                >
                  {restarting === c.name ? <Loader2 className="h-4 w-4 animate-spin" /> : <RotateCw className="h-4 w-4" />}
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
