import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  const target = request.nextUrl.searchParams.get("url");
  // rempart-expect: CODE-SSRF
  const r = await fetch(target!);
  return NextResponse.json({ body: await r.text() });
}
