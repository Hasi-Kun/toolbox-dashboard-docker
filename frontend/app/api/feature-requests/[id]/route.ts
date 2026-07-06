import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  return proxyToBackend(request, `/api/v1/feature-requests/${params.id}`);
}

export async function DELETE(request: NextRequest, { params }: { params: { id: string } }) {
  return proxyToBackend(request, `/api/v1/feature-requests/${params.id}`, { method: "DELETE" });
}
