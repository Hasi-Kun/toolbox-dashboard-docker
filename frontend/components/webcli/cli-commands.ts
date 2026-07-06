import { TOOL_FORMS, type FieldSpec } from "@/lib/tool-forms";

type Tool = { slug: string; name: string; description: string; category: string };

/** Zerlegt eine Eingabezeile in Tokens, respektiert "..."-Anfuehrungszeichen
 * fuer Werte mit Leerzeichen. */
function tokenize(input: string): string[] {
  const tokens: string[] = [];
  const regex = /"([^"]*)"|(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(input)) !== null) {
    tokens.push(match[1] ?? match[2]);
  }
  return tokens;
}

function convertArg(field: FieldSpec, raw: string): unknown {
  switch (field.type) {
    case "number":
      return Number(raw);
    case "checkbox":
      return ["true", "1", "yes", "ja"].includes(raw.toLowerCase());
    case "int-list":
      return raw.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !Number.isNaN(n));
    case "string-list":
      return raw.split(",").map((s) => s.trim()).filter(Boolean);
    case "checkbox-group":
      return raw.split(",").map((s) => s.trim()).filter(Boolean);
    default:
      return raw;
  }
}

export async function executeCommand(
  input: string,
  tools: Tool[]
): Promise<{ lines: string[]; clear?: boolean }> {
  const trimmed = input.trim();
  if (!trimmed) return { lines: [] };

  const tokens = tokenize(trimmed);
  const [command, ...args] = tokens;
  const lower = command.toLowerCase();

  if (lower === "help") {
    return {
      lines: [
        "Verfuegbare eingebaute Befehle:",
        "  help              -- diese Hilfe",
        "  list              -- alle verfuegbaren Tool-Befehle auflisten",
        "  clear             -- Fenster leeren",
        "",
        "Tool-Befehle: <tool-slug> <arg1> <arg2> ...",
        "Beispiel: ping example.com",
        "Beispiel: dns-lookup example.com MX",
        "Werte mit Leerzeichen in \"Anfuehrungszeichen\" setzen.",
        "'list' zeigt alle Slugs und ihre Parameter in der richtigen Reihenfolge.",
      ],
    };
  }

  if (lower === "clear") {
    return { lines: [], clear: true };
  }

  if (lower === "list") {
    const lines = Object.entries(TOOL_FORMS).map(([slug, fields]) => {
      const params = fields.map((f) => f.name).join(" ");
      return `  ${slug.padEnd(28)} ${params}`;
    });
    return { lines: ["Verfuegbare Tool-Befehle (Slug Parameter...):", ...lines] };
  }

  const fields = TOOL_FORMS[lower];
  const toolMeta = tools.find((t) => t.slug === lower);

  if (!fields || !toolMeta) {
    return { lines: [`Unbekannter Befehl: '${command}'. 'help' fuer Hilfe, 'list' fuer alle Tool-Befehle.`] };
  }

  if (toolMeta.category === "nmap" || (toolMeta as unknown as { is_active_scan?: boolean }).is_active_scan) {
    // Aktive Scans koennen 1-2 Minuten dauern -- im CLI-Fenster trotzdem erlaubt,
    // nur ein Hinweis vorab.
  }

  const payload: Record<string, unknown> = {};
  fields.forEach((field, i) => {
    if (i < args.length) {
      payload[field.name] = convertArg(field, args[i]);
    } else if (field.default !== undefined) {
      payload[field.name] = field.default;
    }
  });

  try {
    const res = await fetch(`/api/tools/${lower}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      const detail = Array.isArray(data.detail)
        ? data.detail.map((d: { field?: string; message?: string }) => `${d.field ?? ""}: ${d.message ?? ""}`).join("; ")
        : data.detail ?? "Fehler";
      return { lines: [`Fehler: ${detail}`] };
    }
    return { lines: formatResult(data) };
  } catch {
    return { lines: ["Fehler: Backend nicht erreichbar."] };
  }
}

/** Formatiert ein beliebiges Tool-Ergebnis als einfache Textzeilen fuer die
 * Terminal-Ausgabe (rekursiv, flach eingerueckt). */
function formatResult(value: unknown, indent = 0): string[] {
  const pad = "  ".repeat(indent);
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) {
    if (value.length === 0) return [];
    return value.flatMap((item, i) =>
      typeof item === "object" && item !== null
        ? [`${pad}[${i}]`, ...formatResult(item, indent + 1)]
        : [`${pad}- ${item}`]
    );
  }
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => {
      if (v === null || v === undefined || v === "" || (Array.isArray(v) && v.length === 0)) return [];
      if (typeof v === "object") return [`${pad}${k}:`, ...formatResult(v, indent + 1)];
      return [`${pad}${k}: ${v}`];
    });
  }
  return [`${pad}${value}`];
}
