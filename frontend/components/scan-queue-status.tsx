"use client";

import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

type QueueStatus = {
  current_job: { job_id: string; template: string; target: string | null; started_at: string } | null;
  queue_length: number;
};

function formatElapsed(startedAt: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

export function ScanQueueStatus() {
  const [status, setStatus] = useState<QueueStatus | null>(null);
  const [, forceTick] = useState(0);

  useEffect(() => {
    let active = true;
    function load() {
      fetch("/api/system/scan-queue-status")
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (active) setStatus(data);
        })
        .catch(() => {});
    }
    load();
    const statusInterval = setInterval(load, 5000);
    // Zweiter, schnellerer Tick nur um die "seit Xs"-Anzeige weiterlaufen
    // zu lassen, ohne dafuer jedes Mal neu zu fetchen.
    const tickInterval = setInterval(() => forceTick((n) => n + 1), 1000);
    return () => {
      active = false;
      clearInterval(statusInterval);
      clearInterval(tickInterval);
    };
  }, []);

  if (!status || (!status.current_job && status.queue_length === 0)) return null;

  return (
    <div className="mb-4 rounded-lg border border-base-border bg-base-elevated px-3 py-2 text-xs text-ink-muted">
      {status.current_job && (
        <p className="flex flex-wrap items-center gap-1.5">
          <Loader2 className="h-3 w-3 shrink-0 animate-spin text-signal" />
          <span>Gerade laeuft:</span>
          <span className="font-mono text-ink">{status.current_job.template}</span>
          <span>gegen</span>
          <span className="font-mono text-ink">{status.current_job.target ?? "?"}</span>
          <span>(seit {formatElapsed(status.current_job.started_at)})</span>
        </p>
      )}
      {status.queue_length > 0 && (
        <p className={status.current_job ? "mt-1" : ""}>
          {status.queue_length} weitere{status.queue_length === 1 ? "r" : ""} Scan{status.queue_length === 1 ? "" : "s"} wartet{status.queue_length === 1 ? "" : "en"} in der Warteschlange.
        </p>
      )}
    </div>
  );
}
