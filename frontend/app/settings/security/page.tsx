"use client";

import { useEffect, useState } from "react";
import { Clock, KeyRound, Loader2, MapPin, Plus, ShieldCheck, ShieldOff, Smartphone, Trash2 } from "lucide-react";
import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { isWebAuthnSupported, registerPasskey } from "@/lib/webauthn-client";
import { useLanguage } from "@/components/language-provider";

type Passkey = { id: number; nickname: string; created_at: string };
type TwoFactorStatus = { totp_enabled: boolean; passkeys: Passkey[] };

async function postJson(url: string, body?: unknown) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail ?? "Unbekannter Fehler");
  return data;
}

export default function SecuritySettingsPage() {
  const { t } = useLanguage();
  const [status, setStatus] = useState<TwoFactorStatus | null>(null);
  const [webauthnSupported, setWebauthnSupported] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [changingPassword, setChangingPassword] = useState(false);

  const [totpSetup, setTotpSetup] = useState<{ secret: string; qrCode: string } | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [busy, setBusy] = useState(false);

  const [allowedIps, setAllowedIps] = useState("");
  const [currentIp, setCurrentIp] = useState("");
  const [savingIps, setSavingIps] = useState(false);

  const [sessionTimeoutMinutes, setSessionTimeoutMinutes] = useState<number | null>(null);
  const [effectiveTimeoutMinutes, setEffectiveTimeoutMinutes] = useState<number | null>(null);
  const [savingTimeout, setSavingTimeout] = useState(false);

  async function loadStatus() {
    const res = await fetch("/api/account/2fa");
    if (res.ok) setStatus(await res.json());
  }

  useEffect(() => {
    loadStatus();
    setWebauthnSupported(isWebAuthnSupported());

    fetch("/api/auth/me/security/allowed-ips")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) {
          setAllowedIps(data.allowed_login_ips ?? "");
          setCurrentIp(data.current_ip ?? "");
        }
      })
      .catch(() => {});

    fetch("/api/auth/me/security/session-timeout")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) {
          setSessionTimeoutMinutes(data.session_timeout_minutes);
          setEffectiveTimeoutMinutes(data.effective_minutes);
        }
      })
      .catch(() => {});
  }, []);

  async function handleSaveAllowedIps(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setSavingIps(true);
    try {
      const res = await fetch("/api/auth/me/security/allowed-ips", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ allowed_ips: allowedIps }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? "Speichern fehlgeschlagen");
      setAllowedIps(data.allowed_login_ips ?? "");
      setNotice(t("security.ip_restriction_saved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Speichern fehlgeschlagen");
    } finally {
      setSavingIps(false);
    }
  }

  async function handleSaveSessionTimeout(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setSavingTimeout(true);
    try {
      const res = await fetch("/api/auth/me/security/session-timeout", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_timeout_minutes: sessionTimeoutMinutes }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? "Speichern fehlgeschlagen");
      setSessionTimeoutMinutes(data.session_timeout_minutes);
      setEffectiveTimeoutMinutes(data.effective_minutes);
      setNotice(t("security.auto_logout_saved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Speichern fehlgeschlagen");
    } finally {
      setSavingTimeout(false);
    }
  }

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setChangingPassword(true);
    try {
      await postJson("/api/account/password", { current_password: currentPassword, new_password: newPassword });
      setNotice(t("security.password_changed_notice"));
      setCurrentPassword("");
      setNewPassword("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Aendern fehlgeschlagen");
    } finally {
      setChangingPassword(false);
    }
  }

  async function handleStartTotpSetup() {
    setError(null);
    setBusy(true);
    try {
      const data = await postJson("/api/account/2fa/totp/setup/start");
      setTotpSetup({ secret: data.secret, qrCode: data.qr_code });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Einrichtung fehlgeschlagen");
    } finally {
      setBusy(false);
    }
  }

  async function handleVerifyTotpSetup(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const data = await postJson("/api/account/2fa/totp/setup/verify", { code: totpCode });
      setStatus(data);
      setTotpSetup(null);
      setTotpCode("");
      setNotice(t("security.totp_setup_notice"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Code ungueltig");
    } finally {
      setBusy(false);
    }
  }

  async function handleDisableTotp() {
    if (!confirm("TOTP wirklich deaktivieren?")) return;
    setError(null);
    setBusy(true);
    try {
      const data = await postJson("/api/account/2fa/totp/disable");
      setStatus(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Deaktivieren fehlgeschlagen");
    } finally {
      setBusy(false);
    }
  }

  async function handleAddPasskey() {
    setError(null);
    setBusy(true);
    try {
      const { options } = await postJson("/api/account/2fa/passkey/register/start");
      const credential = await registerPasskey(options);
      const nickname = prompt("Name fuer diesen Passkey (z.B. 'MacBook', 'YubiKey')", "Passkey") ?? "Passkey";
      const data = await postJson("/api/account/2fa/passkey/register/verify", { credential, nickname });
      setStatus(data);
      setNotice(t("security.passkey_added_notice"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Passkey-Einrichtung fehlgeschlagen oder abgebrochen");
    } finally {
      setBusy(false);
    }
  }

  async function handleDeletePasskey(passkey: Passkey) {
    if (!confirm(`Passkey '${passkey.nickname}' wirklich entfernen?`)) return;
    setError(null);
    setBusy(true);
    try {
      const res = await fetch(`/api/account/2fa/passkey/${passkey.id}`, { method: "DELETE" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? "Entfernen fehlgeschlagen");
      setStatus(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Entfernen fehlgeschlagen");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="mx-auto w-full max-w-2xl flex-1 overflow-y-auto p-6">
          <h1 className="font-display text-2xl text-ink">{t("security.title")}</h1>
          <p className="mt-1 text-sm text-ink-muted">{t("security.subtitle")}</p>

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

          <section className="mt-6 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
            <h2 className="font-display text-base text-ink">{t("security.password_heading")}</h2>
            <form onSubmit={handleChangePassword} className="mt-4 space-y-3">
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-ink-muted">{t("security.current_password_label")}</span>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                  className="input"
                />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-ink-muted">{t("security.new_password_label")}</span>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  autoComplete="new-password"
                  minLength={12}
                  required
                  className="input"
                />
              </label>
              <button type="submit" disabled={changingPassword} className="submit-button w-auto px-4">
                {changingPassword ? <Loader2 className="h-4 w-4 animate-spin" /> : t("security.change_password_button")}
              </button>
            </form>
          </section>

          <section className="mt-6 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
            <div className="flex items-center justify-between">
              <h2 className="font-display text-base text-ink">{t("security.totp_heading")}</h2>
              {status && (
                <span className={status.totp_enabled ? "text-xs text-signal" : "text-xs text-ink-muted"}>
                  {status.totp_enabled ? t("security.totp_active") : t("security.totp_not_set_up")}
                </span>
              )}
            </div>

            {status?.totp_enabled && !totpSetup && (
              <div className="mt-4 flex items-center justify-between">
                <p className="text-sm text-ink-muted">{t("security.totp_active_note")}</p>
                <div className="flex gap-2">
                  <button onClick={handleStartTotpSetup} disabled={busy} className="method-button w-auto px-3">
                    <Smartphone className="h-4 w-4" /> {t("security.rotate_button")}
                  </button>
                  <button onClick={handleDisableTotp} disabled={busy} className="method-button w-auto px-3 hover:border-critical/40 hover:text-critical">
                    <ShieldOff className="h-4 w-4" /> {t("security.deactivate_button")}
                  </button>
                </div>
              </div>
            )}

            {!status?.totp_enabled && !totpSetup && (
              <button onClick={handleStartTotpSetup} disabled={busy} className="method-button mt-4">
                <Plus className="h-4 w-4" /> {t("security.setup_totp_button")}
              </button>
            )}

            {totpSetup && (
              <div className="mt-4 space-y-3">
                <p className="text-sm text-ink-muted">{t("security.scan_qr_note")}</p>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={totpSetup.qrCode} alt="TOTP QR-Code" className="mx-auto rounded-lg border border-base-border" />
                <p className="text-center font-mono text-xs text-ink-muted">{totpSetup.secret}</p>
                <form onSubmit={handleVerifyTotpSetup} className="flex gap-2">
                  <input
                    inputMode="numeric"
                    maxLength={6}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                    placeholder="123456"
                    className="input font-mono tracking-widest"
                  />
                  <button type="submit" disabled={busy} className="submit-button w-auto px-4">
                    <ShieldCheck className="h-4 w-4" /> {t("security.confirm_button")}
                  </button>
                </form>
              </div>
            )}
          </section>

          <section className="mt-6 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
            <div className="flex items-center justify-between">
              <h2 className="font-display text-base text-ink">{t("security.passkeys_heading")}</h2>
              {webauthnSupported && (
                <button onClick={handleAddPasskey} disabled={busy} className="method-button w-auto px-3">
                  <Plus className="h-4 w-4" /> {t("security.add_button")}
                </button>
              )}
            </div>

            {!webauthnSupported && (
              <p className="mt-3 text-sm text-ink-muted">{t("security.no_webauthn_support")}</p>
            )}

            <ul className="mt-4 space-y-2">
              {status?.passkeys.map((passkey) => (
                <li
                  key={passkey.id}
                  className="flex items-center justify-between rounded-lg border border-base-border px-3 py-2"
                >
                  <div className="flex items-center gap-2">
                    <KeyRound className="h-4 w-4 text-ink-muted" />
                    <span className="text-sm text-ink">{passkey.nickname}</span>
                  </div>
                  <button
                    onClick={() => handleDeletePasskey(passkey)}
                    disabled={busy}
                    title={t("security.remove_title")}
                    className="rounded-lg border border-base-border p-1.5 text-ink-muted hover:border-critical/40 hover:text-critical"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </li>
              ))}
              {status?.passkeys.length === 0 && (
                <p className="text-sm text-ink-muted">{t("security.no_passkey_yet")}</p>
              )}
            </ul>
          </section>

          <section className="mt-6 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
            <h2 className="flex items-center gap-2 font-display text-base text-ink">
              <MapPin className="h-4 w-4" /> {t("security.ip_restriction_heading")}
            </h2>
            <p className="mt-1 text-sm text-ink-muted">{t("security.ip_restriction_description")}</p>
            <p className="mt-2 text-xs text-ink-muted">
              {t("security.current_ip_label")} <span className="font-mono text-signal">{currentIp}</span>
            </p>
            <form onSubmit={handleSaveAllowedIps} className="mt-3 space-y-3">
              <textarea
                value={allowedIps}
                onChange={(e) => setAllowedIps(e.target.value)}
                placeholder={t("security.ip_restriction_placeholder")}
                rows={2}
                className="input font-mono text-sm"
              />
              <button type="submit" disabled={savingIps} className="submit-button w-auto px-4">
                {savingIps ? <Loader2 className="h-4 w-4 animate-spin" /> : t("common.save")}
              </button>
            </form>
          </section>

          <section className="mt-6 rounded-xl border border-base-border bg-base-elevated p-5 shadow-card">
            <h2 className="flex items-center gap-2 font-display text-base text-ink">
              <Clock className="h-4 w-4" /> {t("security.auto_logout_heading")}
            </h2>
            <p className="mt-1 text-sm text-ink-muted">
              {t("security.auto_logout_description")} {t("security.auto_logout_effective")} {effectiveTimeoutMinutes ?? "..."} min.
            </p>
            <form onSubmit={handleSaveSessionTimeout} className="mt-3 flex flex-wrap items-end gap-3">
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-ink-muted">{t("security.auto_logout_minutes_label")}</span>
                <input
                  type="number"
                  min={5}
                  max={10080}
                  value={sessionTimeoutMinutes ?? ""}
                  onChange={(e) => setSessionTimeoutMinutes(e.target.value ? Number(e.target.value) : null)}
                  placeholder={t("security.auto_logout_placeholder")}
                  className="input w-40"
                />
              </label>
              <button type="submit" disabled={savingTimeout} className="submit-button w-auto px-4">
                {savingTimeout ? <Loader2 className="h-4 w-4 animate-spin" /> : t("common.save")}
              </button>
            </form>
          </section>
        </main>
      </div>
    </div>
  );
}
