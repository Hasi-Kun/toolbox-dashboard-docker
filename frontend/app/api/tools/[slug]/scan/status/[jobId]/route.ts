import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function GET(request: NextRequest, { params }: { params: Promise<{ slug: string; jobId: string }> }) {
  const { slug, jobId } = await params;
  return proxyToBackend(request, `/api/v1/tools/${slug}/scan/status/${jobId}`);
}
