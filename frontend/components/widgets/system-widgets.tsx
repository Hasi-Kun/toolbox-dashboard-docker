"use client";

import { useEffect, useState } from "react";
import { MetricCard } from "@/components/widgets/metric-card";
import { useLanguage } from "@/components/language-provider";

type SystemInfo = {
  cpu_percent: number;
  memory_percent: number;
  memory_used_bytes: number;
  memory_total_bytes: number;
};

type DockerStatus = {
  total: number;
  running: number;
};

function formatBytes(bytes: number): string {
  const gb = bytes / 1024 ** 3;
  return `${gb.toFixed(1)} GB`;
}

export function SystemWidgets() {
  const { t } = useLanguage();
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [docker, setDocker] = useState<DockerStatus | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [infoRes, dockerRes] = await Promise.all([
          fetch("/api/system/info"),
          fetch("/api/system/docker"),
        ]);

        if (infoRes.status === 403 || dockerRes.status === 403) {
          if (!cancelled) setForbidden(true);
          return;
        }
        if (!infoRes.ok || !dockerRes.ok) {
          if (!cancelled) setError(true);
          return;
        }

        const infoData = await infoRes.json();
        const dockerData = await dockerRes.json();
        if (!cancelled) {
          setInfo(infoData);
          setDocker(dockerData);
        }
      } catch {
        if (!cancelled) setError(true);
      }
    }

    load();
    const interval = setInterval(load, 15000); // alle 15s aktualisieren
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (forbidden) {
    return (
      <>
        <MetricCard label={t("dashboard.cpu")} value="—" hint={t("dashboard.admin_only")} />
        <MetricCard label={t("dashboard.ram")} value="—" hint={t("dashboard.admin_only")} />
        <MetricCard label={t("dashboard.docker")} value="—" hint={t("dashboard.admin_only")} />
      </>
    );
  }

  if (error) {
    return (
      <>
        <MetricCard label={t("dashboard.cpu")} value="—" hint={t("dashboard.unreachable")} />
        <MetricCard label={t("dashboard.ram")} value="—" hint={t("dashboard.unreachable")} />
        <MetricCard label={t("dashboard.docker")} value="—" hint={t("dashboard.unreachable")} />
      </>
    );
  }

  return (
    <>
      <MetricCard
        label={t("dashboard.cpu")}
        value={info ? info.cpu_percent.toFixed(0) : "—"}
        unit="%"
        hint={info ? undefined : t("dashboard.connecting")}
      />
      <MetricCard
        label={t("dashboard.ram")}
        value={info ? info.memory_percent.toFixed(0) : "—"}
        unit="%"
        hint={info ? `${formatBytes(info.memory_used_bytes)} / ${formatBytes(info.memory_total_bytes)}` : t("dashboard.connecting")}
      />
      <MetricCard
        label={t("dashboard.docker")}
        value={docker ? `${docker.running}/${docker.total}` : "—"}
        hint={docker ? undefined : t("dashboard.connecting")}
      />
    </>
  );
}
