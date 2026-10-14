import { NextResponse } from "next/server";
import { getAccessToken } from "@/lib/supabase/server";
import { maxUploadBytes } from "@/lib/bff/proxy";

export const dynamic = "force-dynamic";

// The upload limit the UI shows and checks before sending a file. Advisory:
// the BFF enforces it again and the API remains the authority (413).
export async function GET(): Promise<NextResponse> {
  if (!(await getAccessToken())) {
    return NextResponse.json(
      { error: { code: "unauthorized", message: "Not authenticated." } },
      { status: 401 },
    );
  }
  return NextResponse.json(
    { max_upload_bytes: maxUploadBytes() },
    { headers: { "Cache-Control": "no-store" } },
  );
}
