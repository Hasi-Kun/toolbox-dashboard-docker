/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: "standalone",
  async headers() {
    // Bewusst eine pragmatische, nicht maximal strikte CSP: 'unsafe-inline'
    // fuer script-src ist noetig, weil Next.js sein Hydration-Payload
    // (__NEXT_DATA__) per Inline-<script> ausliefert -- eine Nonce-basierte
    // striktere Variante waere moeglich, braucht aber Middleware-Aenderungen
    // (pro Anfrage einen Nonce generieren und in jeden Tag injizieren).
    // img-src erlaubt https: pauschal, da einige Tools (Favicons, externe
    // Bild-Suche) Bilder von wechselnden Fremd-Domains nachladen.
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
    ].join("; ");

    return [
      {
        source: "/(.*)",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "geolocation=(), microphone=(), camera=()" },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
