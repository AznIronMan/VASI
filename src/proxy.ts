import { NextResponse, type NextRequest } from "next/server";

const PAGE_METHODS = new Set(["GET", "HEAD"]);

export function pageMethodDecision(method: string, pathname: string): "allow" | "deny" {
  if (pathname === "/api" || pathname.startsWith("/api/")) return "allow";
  return PAGE_METHODS.has(method.toUpperCase()) ? "allow" : "deny";
}

export function proxy(request: NextRequest) {
  if (pageMethodDecision(request.method, request.nextUrl.pathname) === "allow") {
    return NextResponse.next();
  }
  return new NextResponse(null, {
    headers: {
      Allow: "GET, HEAD",
      "Cache-Control": "no-store",
    },
    status: 405,
  });
}

export const config = {
  matcher: ["/((?!api(?:/|$)|_next(?:/|$)).*)"],
};
