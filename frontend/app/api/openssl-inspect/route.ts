import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.BACKEND_INTERNAL_URL ?? "http://toolbox-backend:8000";

/**
 * Eigener Proxy statt proxyToBackend(), weil ein Datei-Upload
 * (multipart/form-data) nicht durch die generische JSON-Weiterleitung
 * passt -- der Formular-Body muss unveraendert 1:1 durchgereicht werden.
 */
export async function POST(request: NextRequest) {
  const cookie = request.headers.get("cookie") ?? "";
  const contentType = request.headers.get("content-type") ?? "";

  const body = await request.arrayBuffer();

  let backendResponse: Response;
  try {
    backendResponse = await fetch(`${BACKEND_URL}/api/v1/openssl-inspect`, {
      method: "POST",
      headers: {
        "Content-Type": contentType,
        cookie,
        "x-real-ip": request.headers.get("x-real-ip") ?? "",
      },
      body,
      cache: "no-store",
    });
  } catch {
    return NextResponse.json({ detail: "Backend nicht erreichbar" }, { status: 502 });
  }

  const data = await backendResponse.text();
  return new NextResponse(data, {
    status: backendResponse.status,
    headers: { "Content-Type": "application/json" },
  });
}
