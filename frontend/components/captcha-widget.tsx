"use client";

import { useEffect, useRef } from "react";

export type PublicCaptchaConfig = {
  provider: string;
  enabled: boolean;
  site_key: string | null;
};

declare global {
  interface Window {
    turnstile?: {
      render: (container: HTMLElement, options: Record<string, unknown>) => string;
      reset: (widgetId: string) => void;
    };
    grecaptcha?: {
      render: (container: HTMLElement, options: Record<string, unknown>) => number;
      reset: (widgetId: number) => void;
    };
  }
}

const SCRIPT_URLS: Record<string, string> = {
  turnstile: "https://challenges.cloudflare.com/turnstile/v0/api.js",
  recaptcha: "https://www.google.com/recaptcha/api.js?render=explicit",
};

function loadScriptOnce(src: string): void {
  if (document.querySelector(`script[src="${src}"]`)) return;
  const script = document.createElement("script");
  script.src = src;
  script.async = true;
  script.defer = true;
  document.head.appendChild(script);
}

/**
 * Rendert je nach konfiguriertem Anbieter ein Cloudflare-Turnstile- oder
 * Google-reCAPTCHA-Widget. Gibt nichts aus (null), solange kein Captcha
 * konfiguriert ist -- die Login-/Registrierungsseite bleibt dann exakt
 * wie zuvor, ganz ohne Drittanbieter-Skript-Ladung.
 */
export function CaptchaWidget({
  config,
  onToken,
}: {
  config: PublicCaptchaConfig;
  onToken: (token: string | null) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const renderedRef = useRef(false);

  useEffect(() => {
    if (!config.enabled || !config.site_key || config.provider === "none") return;

    const scriptUrl = SCRIPT_URLS[config.provider];
    if (!scriptUrl) return;

    loadScriptOnce(scriptUrl);
    renderedRef.current = false;

    const interval = setInterval(() => {
      if (renderedRef.current || !containerRef.current) return;

      if (config.provider === "turnstile" && window.turnstile) {
        window.turnstile.render(containerRef.current, {
          sitekey: config.site_key,
          callback: (token: string) => onToken(token),
          "expired-callback": () => onToken(null),
          "error-callback": () => onToken(null),
        });
        renderedRef.current = true;
        clearInterval(interval);
      } else if (config.provider === "recaptcha" && window.grecaptcha?.render) {
        window.grecaptcha.render(containerRef.current, {
          sitekey: config.site_key,
          callback: (token: string) => onToken(token),
          "expired-callback": () => onToken(null),
        });
        renderedRef.current = true;
        clearInterval(interval);
      }
    }, 200);

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config.enabled, config.provider, config.site_key]);

  if (!config.enabled || !config.site_key || config.provider === "none") return null;

  return <div ref={containerRef} className="flex justify-center" />;
}
