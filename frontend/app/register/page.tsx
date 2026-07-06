"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { KeyRound, Languages, Loader2, Radar, ShieldCheck, Smartphone } from "lucide-react";
import { registerPasskey, isWebAuthnSupported } from "@/lib/webauthn-client";
import { AnimatedBackground, type BackgroundStyle } from "@/components/animated-background";
import { useLanguage } from "@/components/language-provider";

type Step =
  | { name: "form" }
  | { name: "choose_2fa"; pendingToken: string }
  | { name: "setup_totp"; pendingToken: string; secret: string; qrCode: string };

async function postJson(url: string, body: unknown) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = Array.isArray(data.detail)
      ? data.detail.map((d: { message?: string }) => d.message).join("; ")
      : data.detail ?? "Unbekannter Fehler";
    throw new Error(detail);
  }
  return data;
}

export default function RegisterPage() {
  const router = useRouter();
  const { language, setLanguage, t } = useLanguage();
  const [step, setStep] = useState<Step>({ name: "form" });
  const [inviteCode, setInviteCode] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [appearance, setAppearance] = useState<{
    background_style: BackgroundStyle;
    custom_background_url: string | null;
    animation_speed: number;
    gradient_color: string;
    interactive_dots: boolean;
    form_opacity_percent: number;
    form_blur_px: number;
  }>({
    background_style: "dots",
    custom_background_url: null,
    animation_speed: 1,
    gradient_color: "#35E0C0",
    interactive_dots: true,
    form_opacity_percent: 90,
    form_blur_px: 4,
  });

  useEffect(() => {
    fetch("/api/appearance")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) setAppearance(data);
      })
      .catch(() => {});
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const data = await postJson("/api/auth/register", { invite_code: inviteCode, username, password });
      setStep({ name: "choose_2fa", pendingToken: data.pending_token });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registrierung fehlgeschlagen");
    } finally {
      setLoading(false);
    }
  }

  async function handleStartTotpSetup(pendingToken: string) {
    setError(null);
    setLoading(true);
    try {
      const data = await postJson("/api/auth/2fa/totp/setup/start", { pending_token: pendingToken });
      setStep({ name: "setup_totp", pendingToken, secret: data.secret, qrCode: data.qr_code });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Einrichtung fehlgeschlagen");
    } finally {
      setLoading(false);
    }
  }

  async function handleStartPasskeySetup(pendingToken: string) {
    setError(null);
    setLoading(true);
    try {
      const { options } = await postJson("/api/auth/2fa/passkey/register/start", { pending_token: pendingToken });
      const credential = await registerPasskey(options);
      await postJson("/api/auth/2fa/passkey/register/verify", { pending_token: pendingToken, credential });
      router.push("/");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Passkey-Einrichtung fehlgeschlagen oder abgebrochen");
    } finally {
      setLoading(false);
    }
  }

  async function handleTotpSetupVerifySubmit(e: React.FormEvent, pendingToken: string) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await postJson("/api/auth/2fa/totp/setup/verify", { pending_token: pendingToken, code });
      router.push("/");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Code ungueltig");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden p-6">
      <AnimatedBackground
        style={appearance.background_style}
        customUrl={appearance.custom_background_url}
        speed={appearance.animation_speed}
        gradientColor={appearance.gradient_color}
        interactive={appearance.interactive_dots}
      />
      <button
        type="button"
        onClick={() => setLanguage(language === "de" ? "en" : "de")}
        title={language === "de" ? "Switch to English" : "Auf Deutsch umschalten"}
        className="absolute right-4 top-4 z-10 flex items-center gap-1.5 rounded-lg border border-base-border bg-base-elevated/80 px-2.5 py-1.5 text-xs font-medium uppercase text-ink-muted backdrop-blur-sm hover:text-ink"
      >
        <Languages className="h-3.5 w-3.5" />
        {language}
      </button>

      <div
        className="relative w-full max-w-sm rounded-xl border border-base-border p-6 shadow-card"
        style={{
          backgroundColor: `rgba(17, 26, 46, ${appearance.form_opacity_percent / 100})`,
          backdropFilter: appearance.form_blur_px > 0 ? `blur(${appearance.form_blur_px}px)` : undefined,
        }}
      >
        <div className="mb-6 flex items-center gap-2">
          <Radar className="h-5 w-5 text-signal" strokeWidth={2.5} />
          <span className="font-display text-lg text-ink">toolbox</span>
        </div>

        {error && (
          <p className="mb-4 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
            {error}
          </p>
        )}

        {step.name === "form" && (
          <form onSubmit={handleSubmit} className="space-y-4">
            <Field label="Einladungscode">
              <input
                autoFocus
                value={inviteCode}
                onChange={(e) => setInviteCode(e.target.value)}
                className="input font-mono"
                autoComplete="off"
              />
            </Field>
            <Field label={t("login.username")}>
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="input"
                autoComplete="username"
              />
            </Field>
            <Field label={t("login.password")}>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="mind. 12 Zeichen"
                minLength={12}
                className="input"
                autoComplete="new-password"
              />
            </Field>
            <SubmitButton loading={loading}>Registrieren</SubmitButton>
          </form>
        )}

        {step.name === "choose_2fa" && (
          <div className="space-y-3">
            <p className="text-sm text-ink-muted">{t("login.setup_2fa_intro")}</p>
            <button
              type="button"
              onClick={() => handleStartTotpSetup(step.pendingToken)}
              disabled={loading}
              className="method-button"
            >
              <Smartphone className="h-4 w-4" /> {t("login.totp_app")}
            </button>
            {isWebAuthnSupported() && (
              <button
                type="button"
                onClick={() => handleStartPasskeySetup(step.pendingToken)}
                disabled={loading}
                className="method-button"
              >
                <KeyRound className="h-4 w-4" /> {t("login.setup_passkey")}
              </button>
            )}
          </div>
        )}

        {step.name === "setup_totp" && (
          <div className="space-y-4">
            <p className="text-sm text-ink-muted">{t("login.scan_qr")}</p>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={step.qrCode} alt="TOTP QR-Code" className="mx-auto rounded-lg border border-base-border" />
            <p className="text-center font-mono text-xs text-ink-muted">{step.secret}</p>
            <form onSubmit={(e) => handleTotpSetupVerifySubmit(e, step.pendingToken)} className="space-y-4">
              <Field label={t("login.confirm_code")}>
                <input
                  inputMode="numeric"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className="input font-mono tracking-widest"
                />
              </Field>
              <SubmitButton loading={loading}>
                <ShieldCheck className="h-4 w-4" /> {t("login.finish_setup")}
              </SubmitButton>
            </form>
          </div>
        )}

        {step.name === "form" && (
          <p className="mt-4 text-center text-xs text-ink-muted">
            Schon registriert?{" "}
            <Link href="/login" className="text-signal hover:underline">
              Zum Login
            </Link>
          </p>
        )}
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium text-ink-muted">{label}</span>
      {children}
    </label>
  );
}

function SubmitButton({ loading, children }: { loading: boolean; children: React.ReactNode }) {
  return (
    <button type="submit" disabled={loading} className="submit-button">
      {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : children}
    </button>
  );
}
