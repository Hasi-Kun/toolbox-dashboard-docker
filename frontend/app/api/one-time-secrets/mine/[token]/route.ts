import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function PATCH(request: NextRequest, { params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  return proxyToBackend(request, `/api/v1/one-time-secrets/mine/${token}`, { method: "PATCH" });
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  return proxyToBackend(request, `/api/v1/one-time-secrets/mine/${token}`, { method: "DELETE" });
}
