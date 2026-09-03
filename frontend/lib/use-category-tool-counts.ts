"use client";

import { useEffect, useState } from "react";
import { SPECIAL_TOOLS } from "@/lib/special-tools";

/**
 * Ermittelt die tatsaechliche Anzahl Tools pro Kategorie dynamisch aus
 * /api/tools, statt sich auf statische, haendisch gepflegte Zahlen zu
 * verlassen (siehe categories.ts -- der frueher dort hinterlegte
 * toolCount-Wert veraltete zuverlaessig bei jedem neu hinzugefuegten
 * Tool, siehe gemeldeter Bug "Anzeige 10 aber es sind 12 Tools").
 *
 * Zaehlt zusaetzlich die Datei-Upload-Spezial-Tools mit (siehe
 * special-tools.ts) -- die sind KEINE registrierten Backend-Module und
 * tauchen deshalb nicht in /api/tools auf, werden aber als eigene
 * Kacheln auf der Kategorie-Seite angezeigt. Ohne diese Ergaenzung kam
 * es zum naechsten Zaehler-Bug: "3 Tools" angezeigt bei Zertifikate,
 * obwohl 4 Kacheln sichtbar waren (3 registrierte + 1 Upload-Spezialtool).
 */
export function useCategoryToolCounts(): Record<string, number> {
  const [counts, setCounts] = useState<Record<string, number>>({});

  useEffect(() => {
    fetch("/api/tools")
      .then((res) => (res.ok ? res.json() : []))
      .then((tools: Array<{ category: string }>) => {
        const next: Record<string, number> = {};
        for (const tool of tools) {
          next[tool.category] = (next[tool.category] ?? 0) + 1;
        }
        for (const special of SPECIAL_TOOLS) {
          next[special.category] = (next[special.category] ?? 0) + 1;
        }
        setCounts(next);
      })
      .catch(() => {});
  }, []);

  return counts;
}
