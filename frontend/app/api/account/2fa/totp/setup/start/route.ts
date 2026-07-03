import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function POST(request: NextRequest) {
  return proxyToBackend(request, "/api/v1/auth/me/2fa/totp/setup/start");
}
