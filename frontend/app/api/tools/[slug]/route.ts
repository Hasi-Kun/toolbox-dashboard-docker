import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function POST(request: NextRequest, { params }: { params: { slug: string } }) {
  return proxyToBackend(request, `/api/v1/tools/${params.slug}`);
}
