"use client";

import { useEffect, useState } from "react";
import { Loader2, Save } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { AnimatedBackground, type BackgroundStyle } from "@/components/animated-background";
import { useIsAdmin, AdminOnlyNotice } from "@/components/use-is-admin";
import { useLanguage } from "@/components/language-provider";

export default function AppearanceSettingsPage() {
  const { isAdmin, loaded: adminLoaded } = useIsAdmin();
  const { t } = useLanguage();
  const [style, setStyle] = useState<BackgroundStyle>("dots");
  const [customUrl, setCustomUrl] = useState("");
  const [speed, setSpeed] = useState(1);
  const [gradientColor, setGradientColor] = useState("#35E0C0");
  const [interactiveDots, setInteractiveDots] = useState(true);
  const [formOpacity, setFormOpacity] = useState(90);
  const [formBlur, setFormBlur] = useState(4);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const STYLE_OPTIONS: { value: BackgroundStyle; label: string; description: string }[] = [
    { value: "none", label: t("appearance.style_none_label"), description: t("appearance.style_none_desc") },
    { value: "dots", label: t("appearance.style_dots_label"), description: t("appearance.style_dots_desc") },
    { value: "gradient", label: t("appearance.style_gradient_label"), description: t("appearance.style_gradient_desc") },
    { value: "starfield", label: t("appearance.style_starfield_label"), description: t("appearance.style_starfield_desc") },
    { value: "custom", label: t("appearance.style_custom_label"), description: t("appearance.style_custom_desc") },
  ];

  useEffect(() => {
    fetch("/api/appearance")
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then((data) => {
        setStyle(data.background_style);
        setCustomUrl(data.custom_background_url ?? "");
        setSpeed(data.animation_speed ?? 1);
        setGradientColor(data.gradient_color ?? "#35E0C0");
        setInteractiveDots(data.interactive_dots ?? true);
        setFormOpacity(data.form_opacity_percent ?? 90);
        setFormBlur(data.form_blur_px ?? 4);
      })
      .catch(() => setError(t("appearance.load_error")))
      .finally(() => setLoaded(true));
  }, [t]);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setSaving(true);
    try {
      const res = await fetch("/api/appearance", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          background_style: style,
          custom_background_url: style === "custom" ? customUrl : null,
          animation_speed: speed,
          gradient_color: gradientColor,
          interactive_dots: interactiveDots,
          form_opacity_percent: formOpacity,
          form_blur_px: formBlur,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail ?? "Speichern fehlgeschlagen");
      setNotice(t("appearance.saved_notice"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Speichern fehlgeschlagen");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-2xl flex-1 overflow-y-auto p-6">
          <h1 className="font-display text-2xl text-ink">{t("appearance.title")}</h1>
          <p className="mt-1 text-sm text-ink-muted">{t("appearance.subtitle")}</p>

          {adminLoaded && !isAdmin && <AdminOnlyNotice />}

          {isAdmin && (
            <>

          {error && (
            <p className="mt-4 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              {error}
            </p>
          )}
          {notice && (
            <p className="mt-4 rounded-lg border border-signal/30 bg-signal/10 px-3 py-2 text-sm text-ink">
              {notice}
            </p>
          )}

          {loaded && (
            <form onSubmit={handleSave} className="mt-6 space-y-5 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {STYLE_OPTIONS.map((opt) => (
                  <label
                    key={opt.value}
                    className={`cursor-pointer rounded-lg border p-3 transition-colors ${
                      style === opt.value ? "border-signal/50 bg-signal/5" : "border-base-border hover:border-signal/30"
                    }`}
                  >
                    <input
                      type="radio"
                      name="background_style"
                      value={opt.value}
                      checked={style === opt.value}
                      onChange={() => setStyle(opt.value)}
                      className="sr-only"
                    />
                    <p className="text-sm font-medium text-ink">{opt.label}</p>
                    <p className="mt-0.5 text-xs text-ink-muted">{opt.description}</p>
                  </label>
                ))}
              </div>

              {style === "custom" && (
                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium text-ink-muted">{t("appearance.image_url_label")}</span>
                  <input
                    type="text"
                    value={customUrl}
                    onChange={(e) => setCustomUrl(e.target.value)}
                    placeholder="https://example.com/hintergrund.jpg"
                    className="input"
                  />
                </label>
              )}

              {(style === "dots" || style === "gradient" || style === "starfield") && (
                <label className="block">
                  <span className="mb-1.5 flex items-center justify-between text-xs font-medium text-ink-muted">
                    <span>{t("appearance.speed_label")}</span>
                    <span className="font-mono text-signal">{speed.toFixed(2)}x</span>
                  </span>
                  <input
                    type="range"
                    min={0.25}
                    max={3}
                    step={0.25}
                    value={speed}
                    onChange={(e) => setSpeed(Number(e.target.value))}
                    className="w-full accent-signal"
                  />
                </label>
              )}

              {style === "gradient" && (
                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium text-ink-muted">{t("appearance.gradient_color_label")}</span>
                  <div className="flex items-center gap-3">
                    <input
                      type="color"
                      value={gradientColor}
                      onChange={(e) => setGradientColor(e.target.value)}
                      className="h-9 w-14 cursor-pointer rounded border border-base-border bg-base"
                    />
                    <input
                      type="text"
                      value={gradientColor}
                      onChange={(e) => setGradientColor(e.target.value)}
                      className="input w-32 font-mono"
                      placeholder="#35E0C0"
                    />
                  </div>
                </label>
              )}

              {style === "dots" && (
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={interactiveDots}
                    onChange={(e) => setInteractiveDots(e.target.checked)}
                    className="h-4 w-4 rounded border-base-border"
                  />
                  <span className="text-sm text-ink-muted">
                    {t("appearance.mouse_interaction_label")}
                  </span>
                </label>
              )}

              <div className="border-t border-base-border pt-4">
                <p className="mb-3 text-xs font-medium uppercase tracking-wide text-ink-muted">{t("appearance.login_form_heading")}</p>

                <label className="block">
                  <span className="mb-1.5 flex items-center justify-between text-xs font-medium text-ink-muted">
                    <span>{t("appearance.transparency_label")}</span>
                    <span className="font-mono text-signal">{formOpacity}%</span>
                  </span>
                  <input
                    type="range"
                    min={0}
                    max={100}
                    value={formOpacity}
                    onChange={(e) => setFormOpacity(Number(e.target.value))}
                    className="w-full accent-signal"
                  />
                  <span className="text-xs text-ink-muted">{t("appearance.transparency_note")}</span>
                </label>

                <label className="mt-3 block">
                  <span className="mb-1.5 flex items-center justify-between text-xs font-medium text-ink-muted">
                    <span>{t("appearance.blur_label")}</span>
                    <span className="font-mono text-signal">{formBlur}px</span>
                  </span>
                  <input
                    type="range"
                    min={0}
                    max={20}
                    value={formBlur}
                    onChange={(e) => setFormBlur(Number(e.target.value))}
                    className="w-full accent-signal"
                  />
                </label>
              </div>

              <button type="submit" disabled={saving} className="submit-button w-auto px-4">
                {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                {t("common.save")}
              </button>
            </form>
          )}

          <div className="relative mt-6 h-64 overflow-hidden rounded-xl border border-base-border">
            <p className="absolute left-3 top-3 z-10 text-xs text-ink-muted">
              {t("appearance.preview_label")} {style === "dots" && interactiveDots ? t("appearance.preview_mouse_hint") : ""}
            </p>
            <AnimatedBackground
              style={style}
              customUrl={customUrl || null}
              speed={speed}
              gradientColor={gradientColor}
              interactive={interactiveDots}
              contained
            />
          </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
