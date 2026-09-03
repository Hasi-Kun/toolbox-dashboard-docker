"use client";

import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { SessionGuard } from "@/components/session-guard";

/**
 * Gemeinsames Layout fuer alle authentifizierten Bereiche (Dashboard,
 * Kategorien, Tools, Feature-Requests, Verlauf, Einstellungen) --
 * bewusst als Next.js Route Group "(app)" (Klammern erscheinen NICHT
 * in der URL), damit /login und /register davon unberuehrt bleiben
 * (die haben ihr eigenes, komplett anderes Vollbild-Design ohne
 * Sidebar/Topbar).
 *
 * Behebt einen gemeldeten Bug: vorher hat JEDE einzelne Seite ihre
 * eigene <Sidebar />+<Topbar /> inline gerendert -- beim Wechsel
 * zwischen z.B. zwei Verwaltungs-Seiten (Benutzer -> Audit-Log) wurden
 * dadurch Sidebar UND Topbar komplett neu gemountet, was ALLE ihre
 * internen Datenabrufe (Nutzerinfo, Docker-Status, Favoriten, Tool-
 * Liste fuer die Suche, SSO-Status, ...) bei JEDER Navigation erneut
 * ausgeloest hat. Mit einem gemeinsamen Layout bleiben Sidebar/Topbar
 * als SELBE Komponenteninstanz gemountet, waehrend nur der Inhalt
 * darunter wechselt -- Next.js' App Router behandelt ein layout.tsx
 * genau dafuer: es bleibt ueber Navigationen INNERHALB derselben
 * Route-Gruppe hinweg erhalten.
 */
export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        {children}
      </div>
      <SessionGuard />
    </div>
  );
}
