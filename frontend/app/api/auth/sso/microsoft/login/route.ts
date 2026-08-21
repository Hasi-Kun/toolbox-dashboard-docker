import { NextRequest } from "next/server";
import { proxyRedirectToBackend } from "@/lib/backend-proxy";

export async function GET(request: NextRequest) {
  return proxyRedirectToBackend(request, "/api/v1/auth/sso/microsoft/login");
}
