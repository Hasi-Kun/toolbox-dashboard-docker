import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.BACKEND_INTERNAL_URL ?? "http://toolbox-backend:8000";

/**
 * Leitet einen Request an das interne Backend weiter und reicht dabei
 * Cookies in BEIDE Richtungen durch:
 *  - Request-Cookies (Session) werden an das Backend weitergegeben
 *  - Set-Cookie-Header aus der Backend-Antwort werden an den Browser
 *    durchgereicht
 *
 * Damit bleibt das Backend intern (nur im toolbox-internal-Netzwerk
 * erreichbar), aber das Session-Cookie funktioniert trotzdem same-origin
 * unter {{TOOLBOX_DOMAIN}}, weil der Browser nur je mit dem Frontend
 * spricht.
 */
export async function proxyToBackend(
  request: NextRequest,
  backendPath: string,
  init?: { method?: string; passThroughHeaders?: boolean }
): Promise<NextResponse> {
  const method = init?.method ?? request.method;
  const cookie = request.headers.get("cookie") ?? "";

  let body: string | undefined;
  if (method !== "GET" && method !== "HEAD") {
    body = await request.text();
  }

  let backendResponse: Response;
  try {
    backendResponse = await fetch(`${BACKEND_URL}${backendPath}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        cookie,
        // X-Real-IP wird von Caddy schon fuer das Frontend gesetzt;
        // hier reichen wir sie 1:1 weiter, damit Rate-Limiting im
        // Backend nicht alle Requests unter der internen Docker-IP sieht.
        "x-real-ip": request.headers.get("x-real-ip") ?? "",
      },
      body,
      cache: "no-store",
    });
  } catch {
    return NextResponse.json({ detail: "Backend nicht erreichbar" }, { status: 502 });
  }

  // Fuer Datei-Downloads (z.B. CSV-Export): echten Content-Type/
  // Content-Disposition durchreichen statt pauschal JSON anzunehmen.
  if (init?.passThroughHeaders) {
    const data = await backendResponse.arrayBuffer();
    const response = new NextResponse(data, {
      status: backendResponse.status,
      headers: {
        "Content-Type": backendResponse.headers.get("content-type") ?? "application/octet-stream",
        "Content-Disposition": backendResponse.headers.get("content-disposition") ?? "",
      },
    });
    const setCookieHeaders = backendResponse.headers.getSetCookie?.() ?? [];
    for (const value of setCookieHeaders) {
      response.headers.append("Set-Cookie", value);
    }
    return response;
  }

  const data = await backendResponse.text();
  const response = new NextResponse(data, {
    status: backendResponse.status,
    headers: { "Content-Type": "application/json" },
  });

  // Alle Set-Cookie-Header 1:1 an den Browser durchreichen.
  const setCookieHeaders = backendResponse.headers.getSetCookie?.() ?? [];
  for (const value of setCookieHeaders) {
    response.headers.append("Set-Cookie", value);
  }

  return response;
}
