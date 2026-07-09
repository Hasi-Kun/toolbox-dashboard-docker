import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function GET(request: NextRequest, { params }: { params: { slug: string; jobId: string } }) {
  return proxyToBackend(request, `/api/v1/tools/${params.slug}/scan/status/${params.jobId}`);
}
