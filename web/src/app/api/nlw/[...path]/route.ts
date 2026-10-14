import { NextRequest } from "next/server";
import { proxy, proxyUpload } from "@/lib/bff/proxy";

export const dynamic = "force-dynamic"; // authenticated, tenant-specific: never cached

type Ctx = { params: Promise<{ path: string[] }> };

async function handle(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  const backendPath = "/" + path.join("/");
  return proxy(req, backendPath);
}

export const GET = handle;
export const POST = handle;
export const PATCH = handle;
export const DELETE = handle;

// The ONLY PUT: a dataset version's raw CSV body, streamed (never buffered).
export async function PUT(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return proxyUpload(req, "/" + path.join("/"));
}
