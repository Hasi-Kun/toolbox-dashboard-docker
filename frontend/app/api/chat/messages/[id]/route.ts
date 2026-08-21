import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return proxyToBackend(request, `/api/v1/chat/messages/${id}`, { method: "DELETE" });
}
