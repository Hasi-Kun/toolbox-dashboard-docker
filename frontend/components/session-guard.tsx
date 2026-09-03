"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { LogIn, ShieldAlert } from "lucide-react";
import { useLanguage } from "@/components/language-provider";

const CHECK_INTERVAL_MS = 60_000;
const AUTO_REDIRECT_DELAY_MS = 4_000;

/**
 * Zentrale, EINMALIGE Session-Gueltigkeitspruefung fuer die gesamte
 * authentifizierte App -- im (app)-Layout gemountet, gilt also fuer
 * alle Seiten gleichermassen, statt verstreuter 401-Behandlung in
 * einzelnen Seiten (Topbar/Kategorie-Seite machten das bisher schon
 * jeweils fuer sich, aber inkonsistent und ohne Nutzer-Hinweis).
 *
 * Deckt zwei Faelle ab:
 * 1. Beim Laden/Neuladen einer Seite mit abgelaufener Session -- die
 *    Middleware (proxy.ts) prueft bewusst nur, OB ein Cookie existiert,
 *    nicht ob es serverseitig noch gueltig ist (z.B. Redis-Session
 *    abgelaufen oder nach einem Neustart verloren) -- diese Komponente
 *    schliesst genau diese Luecke mit einer echten Backend-Pruefung.
 * 2. Waehrend der laufenden Nutzung, falls die Session zwischendurch
 *    ablaeuft (periodische Pruefung alle 60s).
 *
 * In beiden Faellen: Popup mit klarer Erklaerung, dann automatische
 * Weiterleitung zur Login-Seite (mit kurzer Verzoegerung, damit der
 * Hinweis auch gelesen werden kann).
 */
export function SessionGuard() {
  const router = useRouter();
  const { t } = useLanguage();
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const res = await fetch("/api/auth/me");
        if (res.status === 401 && !cancelled) {
          setExpired(true);
        }
      } catch {
        // Netzwerkfehler -- bewusst NICHT als abgelaufene Session werten,
        // sonst wuerde eine kurze Verbindungsstoerung faelschlich das
        // Ablauf-Popup ausloesen.
      }
    }

    check();
    const interval = setInterval(check, CHECK_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    if (!expired) return;
    // Das (ungueltig gewordene) Cookie muss VOR dem Redirect entfernt
    // werden -- sonst wuerde die Middleware (proxy.ts) bei /login weiterhin
    // ein Cookie vorfinden (die pruefte ja bewusst nur Praesenz, nicht
    // Gueltigkeit) und sofort wieder zurueck zu "/" leiten: eine
    // Redirect-Schleife. /api/auth/logout loescht das Cookie bedingungslos,
    // auch wenn die Session serverseitig bereits ungueltig/weg ist.
    fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
    const timeout = setTimeout(() => router.push("/login"), AUTO_REDIRECT_DELAY_MS);
    return () => clearTimeout(timeout);
  }, [expired, router]);

  if (!expired) return null;

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center bg-black/70 p-4">
      <div className="glass-card w-full max-w-sm rounded-xl bg-base-elevated p-6 text-center">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-warn/10">
          <ShieldAlert className="h-6 w-6 text-warn" />
        </div>
        <h2 className="mt-4 font-display text-lg text-ink">{t("session_expired.title")}</h2>
        <p className="mt-1.5 text-sm text-ink-muted">{t("session_expired.body")}</p>
        <button type="button" onClick={() => { fetch("/api/auth/logout", { method: "POST" }).finally(() => router.push("/login")); }} className="submit-button mt-5">
          <LogIn className="h-4 w-4" /> {t("session_expired.button")}
        </button>
      </div>
    </div>
  );
}
