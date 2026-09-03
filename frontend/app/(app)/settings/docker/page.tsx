"use client";

import { useIsAdmin, AdminOnlyNotice } from "@/components/use-is-admin";
import { useLanguage } from "@/components/language-provider";
import { DockerStatusModal } from "@/components/widgets/docker-status-modal";

/**
 * Eigene Seite fuer die Docker-Container-Verwaltung (Status + Neustart)
 * -- vorher Teil der Dashboard-Statusleiste, auf Wunsch von dort entfernt
 * (das Dashboard zeigt nur noch Server-Status/CPU/RAM/Online-Nutzer).
 * Die Verwaltungsfunktion selbst bleibt vollstaendig erhalten, jetzt
 * hier unter Verwaltung statt im taeglichen Ueberblick.
 */
export default function DockerSettingsPage() {
  const { isAdmin, loaded } = useIsAdmin();
  const { t } = useLanguage();

  if (!loaded) return null;
  if (!isAdmin) return <AdminOnlyNotice />;

  return (
    <main className="flex-1 overflow-y-auto p-6">
      <h1 className="font-display text-2xl text-ink">{t("docker_settings.title")}</h1>
      <p className="mt-1 text-sm text-ink-muted">{t("docker_settings.subtitle")}</p>

      <div className="mt-6 max-w-lg">
        <DockerStatusModal embedded onClose={() => {}} />
      </div>
    </main>
  );
}
