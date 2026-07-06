import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function PATCH(request: NextRequest, { params }: { params: { id: string } }) {
  return proxyToBackend(request, `/api/v1/feature-requests/${params.id}/status`, { method: "PATCH" });
}
