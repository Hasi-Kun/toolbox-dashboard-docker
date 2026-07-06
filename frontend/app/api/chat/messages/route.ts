import { NextRequest } from "next/server";
import { proxyToBackend } from "@/lib/backend-proxy";

export async function GET(request: NextRequest) {
  return proxyToBackend(request, "/api/v1/chat/messages");
}

export async function POST(request: NextRequest) {
  return proxyToBackend(request, "/api/v1/chat/messages");
}
