import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function POST(request: NextRequest, { params }: { params: Promise<{ containerName: string }> }) {
  const { containerName } = await params;
  return proxyToBackend(request, `/api/v1/system/docker/${containerName}/restart`, { method: "POST" });
}
