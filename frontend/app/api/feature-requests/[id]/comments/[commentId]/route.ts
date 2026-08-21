import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string; commentId: string }> }) {
  const { id, commentId } = await params;
  return proxyToBackend(request, `/api/v1/feature-requests/${id}/comments/${commentId}`, { method: "DELETE" });
}
