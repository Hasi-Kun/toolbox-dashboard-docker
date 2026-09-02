import { NextRequest, NextResponse } from "next/server";

const SESSION_COOKIE_NAME = "toolbox_session";
// "/s/" (OneTimePassword-Ansichtsseite) ist bewusst oeffentlich -- der
// Empfaenger eines geteilten Geheimnis-Links hat typischerweise KEIN
// eigenes Toolbox-Konto. Die Seite selbst ruft das Geheimnis NICHT
// automatisch beim Laden ab (nur nach explizitem Klick) -- sonst wuerden
// automatische Link-Vorschauen (Slack/Teams/etc. Crawler-Bots, die die
// URL beim Teilen selbst aufrufen) das Einmal-Geheimnis vorzeitig
// "verbrennen", bevor der eigentliche Empfaenger es je sieht.
const PUBLIC_PATHS = ["/login", "/register", "/s/"];

/**
 * Sperrt das gesamte Dashboard ohne gueltiges Session-Cookie.
 *
 * Bewusst nur eine Praesenz-Pruefung (Cookie da oder nicht) -- die
 * eigentliche Gueltigkeitspruefung (Session in Redis, User aktiv?)
 * passiert bei jedem echten API-Call ohnehin im Backend ueber
 * `get_current_user`. Die Middleware verhindert nur, dass eine
 * ausgeloggte Person ueberhaupt Seiteninhalt zu sehen bekommt.
 *
 * Umbenannt von middleware.ts zu proxy.ts (Next.js 16 -- middleware.ts
 * ist deprecated, laeuft nur noch im Edge-Runtime-Fallback). Logik
 * unveraendert, nur Dateiname + Funktionsname per Migrationsanleitung
 * angepasst.
 */
export default function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  const isPublic = PUBLIC_PATHS.some((path) => pathname.startsWith(path));
  const hasSession = request.cookies.has(SESSION_COOKIE_NAME);

  if (!isPublic && !hasSession) {
    const loginUrl = new URL("/login", request.url);
    return NextResponse.redirect(loginUrl);
  }

  if (pathname === "/login" && hasSession) {
    return NextResponse.redirect(new URL("/", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Alles außer:
     * - api-Routen (die pruefen Auth selbst gegen das Backend)
     * - Next.js-interne Assets (_next/static, _next/image)
     * - favicon
     */
    "/((?!api|_next/static|_next/image|favicon.ico).*)",
  ],
};
