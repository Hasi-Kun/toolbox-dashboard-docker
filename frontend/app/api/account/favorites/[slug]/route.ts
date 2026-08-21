import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return proxyToBackend(request, `/api/v1/auth/me/favorites/${slug}`, { method: "DELETE" });
}
