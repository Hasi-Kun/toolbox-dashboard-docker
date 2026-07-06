"use client";

import { useEffect, useState } from "react";
import { Loader2, Save, Sparkles } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { StyledUsername } from "@/components/styled-username";
import { useMe } from "@/components/use-is-admin";

const STYLES: { value: string; label: string }[] = [
  { value: "default", label: "Standard" },
  { value: "solid", label: "Einfarbig" },
  { value: "gradient", label: "Farbverlauf" },
  { value: "particles", label: "Glanz-Effekt" },
  { value: "twinkle", label: "Twinkle" },
  { value: "glitter", label: "Glitter" },
  { value: "rainbow", label: "Regenbogen" },
];

export default function DisplayStylePage() {
  const { me, loaded } = useMe();
  const [style, setStyle] = useState("default");
  const [color, setColor] = useState("#35E0C0");
  const [gradientColor, setGradientColor] = useState("#F5C518");
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/auth/me/display-style")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) {
          setStyle(data.display_name_style);
          setColor(data.display_name_color);
          setGradientColor(data.display_name_gradient_color);
        }
      })
      .catch(() => {});
  }, []);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const res = await fetch("/api/auth/me/display-style", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          display_name_style: style, display_name_color: color, display_name_gradient_color: gradientColor,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail ?? "Speichern fehlgeschlagen");
      setNotice("Gespeichert!");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Speichern fehlgeschlagen");
    } finally {
      setSaving(false);
    }
  }

  const isPremium = Boolean(me?.is_premium);

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-xl flex-1 overflow-y-auto p-6">
          <h1 className="flex items-center gap-2 font-display text-2xl text-ink">
            <Sparkles className="h-5 w-5 text-signal" /> Anzeigename-Style
          </h1>
          <p className="mt-1 text-sm text-ink-muted">
            Gestalte, wie dein Name in der Shoutbox und der Topbar erscheint. Premium-Feature.
          </p>

          {loaded && !isPremium && (
            <p className="mt-6 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              Das ist ein Premium-Feature. Ein Administrator kann dir Premium unter "Benutzer" freischalten.
            </p>
          )}

          {isPremium && (
            <form onSubmit={handleSave} className="mt-6 space-y-4 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
              {error && <p className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</p>}
              {notice && <p className="rounded-lg border border-signal/30 bg-signal/10 px-3 py-2 text-sm text-signal">{notice}</p>}

              <div>
                <p className="mb-2 text-xs font-medium text-ink-muted">Vorschau</p>
                <div className="rounded-lg border border-base-border bg-base p-4">
                  <StyledUsername
                    username={me?.username ?? "DeinName"}
                    role={me?.role ?? "member"}
                    isPremium
                    displayNameStyle={style}
                    displayNameColor={color}
                    displayNameGradientColor={gradientColor}
                    premiumBadgeColor={me?.premium_badge_color}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {STYLES.map((s) => (
                  <button
                    key={s.value}
                    type="button"
                    onClick={() => setStyle(s.value)}
                    className={`rounded-lg border p-2 text-xs transition-colors ${
                      style === s.value ? "border-signal/50 bg-signal/10 text-signal" : "border-base-border text-ink-muted hover:border-signal/30"
                    }`}
                  >
                    {s.label}
                  </button>
                ))}
              </div>

              {style !== "default" && style !== "rainbow" && (
                <div className="flex gap-4">
                  <label className="block">
                    <span className="mb-1.5 block text-xs font-medium text-ink-muted">Farbe</span>
                    <input type="color" value={color} onChange={(e) => setColor(e.target.value)} className="h-9 w-16 rounded border border-base-border bg-base" />
                  </label>
                  {(style === "gradient" || style === "twinkle") && (
                    <label className="block">
                      <span className="mb-1.5 block text-xs font-medium text-ink-muted">Verlaufsfarbe</span>
                      <input type="color" value={gradientColor} onChange={(e) => setGradientColor(e.target.value)} className="h-9 w-16 rounded border border-base-border bg-base" />
                    </label>
                  )}
                </div>
              )}
              {style === "rainbow" && (
                <p className="text-xs text-ink-muted">Der Regenbogen-Stil zyklt automatisch durch alle Farben, keine Einstellung noetig.</p>
              )}

              <button type="submit" disabled={saving} className="submit-button w-auto px-4">
                {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                Speichern
              </button>
            </form>
          )}
        </main>
      </div>
    </div>
  );
}
