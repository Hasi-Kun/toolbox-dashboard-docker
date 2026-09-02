"use client";

import { useEffect, useState } from "react";
import { Activity, Boxes, Cpu, MemoryStick, Users } from "lucide-react";
import { useLanguage } from "@/components/language-provider";
import { useCountUp } from "@/lib/use-count-up";
import { DockerStatusModal } from "@/components/widgets/docker-status-modal";

type Status = "online" | "degraded" | "offline";

type SystemInfo = {
  cpu_percent: number;
  memory_percent: number;
  memory_used_bytes: number;
  memory_total_bytes: number;
};

type DockerStatus = { total: number; running: number };
type OnlineUsers = { count: number; usernames: string[] };

function formatBytes(bytes: number): string {
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}

const statusColor: Record<Status, string> = {
  online: "bg-signal",
  degraded: "bg-warn",
  offline: "bg-critical",
};

/**
 * Ersetzt die urspruenglichen 4-5 einzeln umrandeten Karten durch eine
 * ruhige, aber jetzt visuell reichere Reihe individueller Statuskarten
 * (Icon, animierte Count-up-Zahl, Mini-Fortschrittsbalken, gestaffelte
 * Einblend-Animation) -- deutlich naeher an einem hochwertigen
 * Dashboard-Look, ohne die urspruenglich behobene Unordnung (5 separat
 * umrandete Boxen mit doppeltem Rahmen+Schatten-Gewicht) wieder
 * einzufuehren: alle Karten teilen sich denselben visuellen Rhythmus.
 */
export function SystemStatusBar() {
  const { t } = useLanguage();
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [docker, setDocker] = useState<DockerStatus | null>(null);
  const [online, setOnline] = useState<OnlineUsers | null>(null);
  const [restricted, setRestricted] = useState(false);
  const [dockerModalOpen, setDockerModalOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [infoRes, dockerRes, onlineRes] = await Promise.all([
          fetch("/api/system/info"),
          fetch("/api/system/docker"),
          fetch("/api/system/online-users"),
        ]);
        if (infoRes.status === 403 || dockerRes.status === 403) {
          if (!cancelled) setRestricted(true);
        } else if (infoRes.ok && dockerRes.ok) {
          if (!cancelled) {
            setInfo(await infoRes.json());
            setDocker(await dockerRes.json());
          }
        }
        if (onlineRes.ok && !cancelled) setOnline(await onlineRes.json());
      } catch {
        // Stumm fehlschlagen -- die Karten zeigen dann einfach "--" statt einer Fehlermeldung.
      }
    }

    load();
    const interval = setInterval(load, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const status: Status = "online";
  const cpu = useCountUp(info?.cpu_percent ?? 0);
  const ram = useCountUp(info?.memory_percent ?? 0);
  const dockerRunning = useCountUp(docker?.running ?? 0);
  const onlineCount = useCountUp(online?.count ?? 0);

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <div
        className="card-interactive sheen relative overflow-hidden rounded-xl border border-base-border bg-base-elevated p-4 shadow-card animate-stagger-in"
        style={{ animationDelay: "0ms" }}
      >
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${statusColor[status]} opacity-40`} />
            <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${statusColor[status]}`} />
          </span>
          <span className="text-xs text-ink-muted">{t("dashboard.server_status")}</span>
        </div>
        <p className="mt-2 font-display text-lg text-ink">
          {status === "online" ? t("dashboard.status_online") : status === "degraded" ? t("dashboard.status_degraded") : t("dashboard.status_offline")}
        </p>
      </div>

      {restricted ? (
        <div className="card-interactive col-span-2 flex items-center rounded-xl border border-base-border bg-base-elevated p-4 shadow-card animate-stagger-in" style={{ animationDelay: "60ms" }}>
          <span className="text-sm text-ink-muted">{t("dashboard.admin_only")}</span>
        </div>
      ) : (
        <>
          <StatCard
            icon={Cpu}
            label={t("dashboard.cpu")}
            value={`${cpu.toFixed(0)}%`}
            progress={info ? info.cpu_percent : 0}
            delayMs={60}
          />
          <StatCard
            icon={MemoryStick}
            label={t("dashboard.ram")}
            value={`${ram.toFixed(0)}%`}
            hint={info ? `${formatBytes(info.memory_used_bytes)} / ${formatBytes(info.memory_total_bytes)}` : undefined}
            progress={info ? info.memory_percent : 0}
            delayMs={120}
          />
          <StatCard
            icon={Boxes}
            label={t("dashboard.docker")}
            value={docker ? `${Math.round(dockerRunning)}/${docker.total}` : "—"}
            progress={docker && docker.total > 0 ? (docker.running / docker.total) * 100 : 0}
            delayMs={180}
            onClick={() => setDockerModalOpen(true)}
          />
        </>
      )}

      <div
        className="card-interactive rounded-xl border border-base-border bg-base-elevated p-4 shadow-card animate-stagger-in"
        style={{ animationDelay: "240ms" }}
      >
        <div className="flex items-center gap-2 text-ink-muted">
          <Users className="h-3.5 w-3.5" />
          <span className="text-xs">{t("dashboard.online_users")}</span>
        </div>
        <p className="mt-2 font-display text-lg text-ink">{online ? Math.round(onlineCount) : "—"}</p>
        {online && online.usernames.length > 0 && (
          <p className="mt-0.5 truncate text-xs text-ink-muted" title={online.usernames.join(", ")}>
            {online.usernames.join(", ")}
          </p>
        )}
      </div>

      {dockerModalOpen && <DockerStatusModal onClose={() => setDockerModalOpen(false)} />}
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  hint,
  progress,
  delayMs,
  onClick,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  hint?: string;
  progress: number;
  delayMs: number;
  onClick?: () => void;
}) {
  const barColor = progress >= 85 ? "bg-critical" : progress >= 65 ? "bg-warn" : "bg-signal";
  const Wrapper = onClick ? "button" : "div";

  return (
    <Wrapper
      type={onClick ? "button" : undefined}
      onClick={onClick}
      className={`card-interactive rounded-xl border border-base-border bg-base-elevated p-4 text-left shadow-card animate-stagger-in ${onClick ? "cursor-pointer" : ""}`}
      style={{ animationDelay: `${delayMs}ms` }}
    >
      <div className="flex items-center gap-2 text-ink-muted">
        <Icon className="h-3.5 w-3.5" />
        <span className="text-xs">{label}</span>
      </div>
      <p className="mt-2 font-display text-lg text-ink" title={hint}>
        {value}
      </p>
      <div className="mt-2 h-1 overflow-hidden rounded-full bg-base">
        <div
          className={`h-full rounded-full ${barColor} transition-[width] duration-700 ease-out`}
          style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
        />
      </div>
    </Wrapper>
  );
}
