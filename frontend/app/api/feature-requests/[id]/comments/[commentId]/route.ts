import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function DELETE(request: NextRequest, { params }: { params: { id: string; commentId: string } }) {
  return proxyToBackend(request, `/api/v1/feature-requests/${params.id}/comments/${params.commentId}`, { method: "DELETE" });
}
