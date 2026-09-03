export type SpecialTool = {
  slug: string;
  category: string;
  name: string;
  description: string;
  badge: string;
};

/**
 * Datei-Upload-Tools, die NICHT als regulaeres Backend-Modul registriert
 * sind (multipart/form-data statt des generischen Pydantic-JSON-Musters
 * aller anderen Tools) -- deshalb tauchen sie nicht in /api/tools auf und
 * brauchen eine eigene Seite. Frueher direkt in der Kategorie-Seite
 * hardcodiert (einmal pro Kategorie), was dazu fuehrte, dass die
 * Tool-Anzahl-Anzeige (aus /api/tools berechnet) diese Tools nicht
 * mitgezaehlt hat -- z.B. "3 Tools" bei Zertifikate, obwohl 4 Kacheln zu
 * sehen waren. Jetzt eine EINZIGE Quelle, die sowohl fuer die Kacheln
 * (category/[slug]/page.tsx) als auch fuer die Zaehlung
 * (use-category-tool-counts.ts) genutzt wird.
 */
export const SPECIAL_TOOLS: SpecialTool[] = [
  {
    slug: "openssl-file-inspector",
    category: "certificates",
    name: "OpenSSL Datei-Inspektor",
    description: "Zertifikat, PKCS#7/S-MIME oder CSR hochladen und analysieren -- Datei wird sofort danach geloescht.",
    badge: "Upload",
  },
  {
    slug: "canary-token-scan",
    category: "security",
    name: "Canary-Token-Scanner",
    description: "Office-Dokumente/PDFs auf eingebettete Tracking-URLs pruefen -- ohne die Datei zu oeffnen, ohne Netzwerkanfrage.",
    badge: "Upload",
  },
];
