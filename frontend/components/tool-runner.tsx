"use client";

import { useState } from "react";
import { Copy, Loader2, Play } from "lucide-react";
import { JsonResult } from "@/components/json-result";
import { CopyButton } from "@/components/copy-button";
import type { FieldSpec } from "@/lib/tool-forms";

type FormValue = string | number | boolean | string[];

function initialValues(fields: FieldSpec[]): Record<string, FormValue> {
  const values: Record<string, FormValue> = {};
  for (const field of fields) {
    if (field.default !== undefined) {
      values[field.name] = field.default;
    } else if (field.type === "checkbox") {
      values[field.name] = false;
    } else if (field.type === "checkbox-group") {
      values[field.name] = [];
    } else if (field.type === "number") {
      values[field.name] = 0;
    } else {
      values[field.name] = "";
    }
  }
  return values;
}

/** Baut aus den Formularwerten den Request-Body -- wandelt z.B. "int-list"
 * (kommagetrennter Text) in ein echtes number[] um, wie es die Backend-
 * Pydantic-Modelle erwarten. */
function buildPayload(fields: FieldSpec[], values: Record<string, FormValue>): Record<string, unknown> {
  const payload: Record<string, unknown> = {};
  for (const field of fields) {
    const raw = values[field.name];
    if (field.type === "int-list") {
      const text = String(raw ?? "");
      payload[field.name] = text
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((s) => parseInt(s, 10))
        .filter((n) => !Number.isNaN(n));
    } else if (field.type === "string-list") {
      const text = String(raw ?? "");
      payload[field.name] = text
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    } else if (field.type === "header-list") {
      const text = String(raw ?? "");
      const headers: Record<string, string> = {};
      for (const line of text.split("\n")) {
        const [key, ...rest] = line.split(":");
        if (key && rest.length > 0) {
          headers[key.trim()] = rest.join(":").trim();
        }
      }
      payload[field.name] = headers;
    } else if (field.type === "number") {
      payload[field.name] = Number(raw);
    } else if (field.name === "version" && field.type === "select") {
      // uuid-generator erwartet ein int, nicht einen string
      payload[field.name] = Number(raw);
    } else if (raw === "" && field.name === "secret") {
      // optionale Secret-Felder: leerer String -> nicht mitschicken (None im Backend)
      continue;
    } else if (raw === "" && field.name === "selector") {
      continue;
    } else {
      payload[field.name] = raw;
    }
  }
  return payload;
}

export function ToolRunner({ slug, fields }: { slug: string; fields: FieldSpec[] }) {
  const [values, setValues] = useState<Record<string, FormValue>>(() => initialValues(fields));
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function setValue(name: string, value: FormValue) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const payload = buildPayload(fields, values);
      const res = await fetch(`/api/tools/${slug}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        const detail = Array.isArray(data.detail)
          ? data.detail.map((d: { field?: string; message?: string }) => `${d.field ?? ""}: ${d.message ?? ""}`).join("; ")
          : data.detail ?? "Unbekannter Fehler";
        throw new Error(detail);
      }
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unbekannter Fehler");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={handleSubmit} className="space-y-4 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
        {fields.map((field) => (
          <FormField key={field.name} field={field} value={values[field.name]} onChange={(v) => setValue(field.name, v)} />
        ))}

        <button type="submit" disabled={loading} className="submit-button w-auto px-5">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          {loading ? "Laeuft..." : "Ausfuehren"}
        </button>
      </form>

      {error && (
        <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>
      )}

      {result !== null && (
        <div className="rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="font-display text-sm text-ink-muted">Ergebnis</h3>
            <button
              type="button"
              onClick={() => navigator.clipboard.writeText(JSON.stringify(result, null, 2)).catch(() => {})}
              className="flex items-center gap-1.5 rounded-lg border border-base-border px-2.5 py-1 text-xs text-ink-muted hover:text-ink"
            >
              <Copy className="h-3.5 w-3.5" /> Alles kopieren
            </button>
          </div>
          <JsonResult data={result} />
        </div>
      )}
    </div>
  );
}

function FormField({
  field,
  value,
  onChange,
}: {
  field: FieldSpec;
  value: FormValue;
  onChange: (value: FormValue) => void;
}) {
  return (
    <div>
      <label className="mb-1.5 block text-xs font-medium text-ink-muted">{field.label}</label>

      {field.type === "text" && (
        <input
          type="text"
          value={value as string}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          className="input"
        />
      )}

      {field.type === "textarea" && (
        <textarea
          value={value as string}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          rows={4}
          className="input font-mono text-sm"
        />
      )}

      {field.type === "int-list" && (
        <input
          type="text"
          value={value as string}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          className="input font-mono"
        />
      )}

      {field.type === "string-list" && (
        <input
          type="text"
          value={value as string}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          className="input font-mono"
        />
      )}

      {field.type === "header-list" && (
        <textarea
          value={value as string}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          rows={3}
          className="input font-mono text-sm"
        />
      )}

      {field.type === "number" && (
        <input
          type="number"
          value={value as number}
          onChange={(e) => onChange(Number(e.target.value))}
          className="input w-32"
        />
      )}

      {field.type === "checkbox" && (
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={value as boolean}
            onChange={(e) => onChange(e.target.checked)}
            className="h-4 w-4 rounded border-base-border"
          />
          <span className="text-sm text-ink-muted">Aktiviert</span>
        </label>
      )}

      {field.type === "select" && (
        <select value={value as string} onChange={(e) => onChange(e.target.value)} className="input w-48">
          {field.options?.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      )}

      {field.type === "checkbox-group" && (
        <div className="flex flex-wrap gap-3">
          {field.options?.map((opt) => {
            const selected = (value as string[]).includes(opt.value);
            return (
              <label key={opt.value} className="flex items-center gap-1.5 text-sm text-ink-muted">
                <input
                  type="checkbox"
                  checked={selected}
                  onChange={(e) => {
                    const current = value as string[];
                    onChange(e.target.checked ? [...current, opt.value] : current.filter((v) => v !== opt.value));
                  }}
                  className="h-4 w-4 rounded border-base-border"
                />
                {opt.label}
              </label>
            );
          })}
        </div>
      )}

      {field.helpText && <p className="mt-1 text-xs text-ink-muted">{field.helpText}</p>}
    </div>
  );
}
