import { Check, X } from "lucide-react";
import { CopyButton } from "@/components/copy-button";

/**
 * Rendert beliebige JSON-Ergebnisse lesbar, ohne dass jedes der Tools eine
 * eigene Ergebnis-Ansicht braucht.
 *
 * Zwei Kernprinzipien:
 * 1. Leere Werte (null, "", [], {} sowie Objekte/Arrays, die nur aus
 *    leeren Werten bestehen) werden komplett weggelassen -- kein Feld,
 *    keine Zeile, kein "—". Das war der Hauptgrund fuer das unruhige
 *    Layout bei z.B. Nmap-Ergebnissen (viele null-Felder wie product/
 *    version bei geschlossenen Ports).
 * 2. Arrays von "flachen" Objekten (z.B. Port-Listen) werden als echte
 *    Tabelle gerendert statt als gestapelte, tief verschachtelte Karten --
 *    Spalten, die ueber alle Zeilen hinweg komplett leer sind, werden
 *    ebenfalls weggelassen.
 */
export function JsonResult({ data }: { data: unknown }) {
  if (isEmptyValue(data)) {
    return <p className="text-sm text-ink-muted">Keine Daten.</p>;
  }
  return <ValueRenderer value={data} depth={0} />;
}

function isEmptyValue(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (typeof value === "string") return value.trim() === "";
  if (Array.isArray(value)) return value.every(isEmptyValue);
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    return entries.length === 0 || entries.every(([, v]) => isEmptyValue(v));
  }
  return false; // Zahlen (inkl. 0) und Booleans (inkl. false) sind NIE "leer"
}

function isFlatObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  return Object.values(value).every((v) => v === null || v === undefined || typeof v !== "object");
}

function humanizeKey(key: string): string {
  return key.replace(/_/g, " ");
}

function ValueRenderer({ value, depth }: { value: unknown; depth: number }) {
  if (isEmptyValue(value)) {
    return <span className="text-ink-muted">—</span>;
  }

  if (typeof value === "boolean") {
    return value ? (
      <Check className="inline h-4 w-4 text-signal" />
    ) : (
      <X className="inline h-4 w-4 text-critical" />
    );
  }

  if (typeof value === "number") {
    return (
      <span className="inline-flex items-center gap-1">
        <span className="font-mono text-ink">{value}</span>
        <CopyButton text={String(value)} />
      </span>
    );
  }

  if (typeof value === "string") {
    if (value.length > 60 || value.includes("\n")) {
      return (
        <span className="flex items-start gap-1.5">
          <pre className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-xs text-ink">{value}</pre>
          <CopyButton text={value} className="mt-0.5" />
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1">
        <span className="text-ink">{value}</span>
        <CopyButton text={value} />
      </span>
    );
  }

  if (Array.isArray(value)) {
    const items = value.filter((v) => !isEmptyValue(v));
    if (items.length === 0) return <span className="text-ink-muted">—</span>;

    const allFlatObjects = items.length > 1 && items.every(isFlatObject);
    if (allFlatObjects) {
      return <ObjectTable items={items as Record<string, unknown>[]} />;
    }

    const allPrimitive = items.every((v) => typeof v !== "object");
    if (allPrimitive) {
      return (
        <div className="flex flex-wrap gap-1.5">
          {items.map((v, i) => (
            <span key={i} className="rounded-md border border-base-border bg-base px-2 py-0.5 font-mono text-xs text-ink">
              <ValueRenderer value={v} depth={depth + 1} />
            </span>
          ))}
        </div>
      );
    }

    return (
      <div className="space-y-2">
        {items.map((item, i) => (
          <div key={i} className="rounded-lg border border-base-border p-3">
            <ValueRenderer value={item} depth={depth + 1} />
          </div>
        ))}
      </div>
    );
  }

  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => !isEmptyValue(v));
    if (entries.length === 0) return <span className="text-ink-muted">—</span>;

    return (
      <dl className={depth === 0 ? "space-y-2.5" : "space-y-1.5"}>
        {entries.map(([key, val]) => {
          if (key === "map_embed_url" && typeof val === "string") {
            return (
              <div key={key} className="pt-1">
                <iframe
                  src={val}
                  className="h-64 w-full rounded-lg border border-base-border"
                  loading="lazy"
                  title="Standort-Karte"
                />
              </div>
            );
          }
          if (key === "transcript" && Array.isArray(val)) {
            const transcriptText = (val as string[]).join("\n");
            return (
              <div key={key} className="group pt-1">
                <div className="mb-1 flex justify-end">
                  <CopyButton text={transcriptText} className="opacity-100" />
                </div>
                <pre className="max-h-96 overflow-y-auto rounded-lg border border-base-border bg-base p-3 font-mono text-xs leading-relaxed text-ink">
                  {(val as string[]).map((line, i) => (
                    <div
                      key={i}
                      className={
                        line.startsWith(">") ? "text-signal" : line.startsWith("[") ? "text-warn" : "text-ink"
                      }
                    >
                      {line}
                    </div>
                  ))}
                </pre>
              </div>
            );
          }
          return (
            <div
              key={key}
              className={
                depth === 0
                  ? "group grid grid-cols-[auto_1fr] items-baseline gap-x-4 gap-y-1 border-b border-base-border pb-2"
                  : "group grid grid-cols-[auto_1fr] items-baseline gap-x-3 gap-y-1"
              }
            >
              <dt className="whitespace-nowrap text-xs font-medium uppercase tracking-wide text-ink-muted">
                {humanizeKey(key)}
              </dt>
              <dd className="min-w-0">
                <ValueRenderer value={val} depth={depth + 1} />
              </dd>
            </div>
          );
        })}
      </dl>
    );
  }

  return <span className="text-ink-muted">{String(value)}</span>;
}

/** Echte Tabelle fuer Arrays gleichartiger flacher Objekte (z.B. Port-Listen).
 * Spalten, die in ALLEN Zeilen leer sind, werden komplett weggelassen. */
function ObjectTable({ items }: { items: Record<string, unknown>[] }) {
  const allKeys = Array.from(new Set(items.flatMap((item) => Object.keys(item))));
  const columns = allKeys.filter((key) => items.some((item) => !isEmptyValue(item[key])));

  if (columns.length === 0) return <span className="text-ink-muted">—</span>;

  return (
    <div className="overflow-x-auto rounded-lg border border-base-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-base-border bg-base text-left text-xs uppercase tracking-wide text-ink-muted">
            {columns.map((col) => (
              <th key={col} className="whitespace-nowrap px-3 py-2 font-medium">
                {humanizeKey(col)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {items.map((item, i) => (
            <tr key={i} className="border-b border-base-border/60 last:border-0">
              {columns.map((col) => (
                <td key={col} className="group px-3 py-2 align-top">
                  <ValueRenderer value={item[col]} depth={99} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
