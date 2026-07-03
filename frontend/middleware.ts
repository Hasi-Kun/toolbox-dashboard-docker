import { NextRequest, NextResponse } from "next/server";

const SESSION_COOKIE_NAME = "toolbox_session";
const PUBLIC_PATHS = ["/login"];

/**
 * Sperrt das gesamte Dashboard ohne gueltiges Session-Cookie.
 *
 * Bewusst nur eine Praesenz-Pruefung (Cookie da oder nicht) -- die
 * eigentliche Gueltigkeitspruefung (Session in Redis, User aktiv?)
 * passiert bei jedem echten API-Call ohnehin im Backend ueber
 * `get_current_user`. Die Middleware verhindert nur, dass eine
 * ausgeloggte Person ueberhaupt Seiteninhalt zu sehen bekommt.
 */
export function middleware(request: NextRequest) {
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
