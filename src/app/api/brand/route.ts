import { resolveProductBrand } from "@/lib/branding";
import { getRuntimeSettings } from "@/lib/runtime-settings";

export const dynamic = "force-dynamic";

export async function GET() {
  return Response.json(resolveProductBrand(await getRuntimeSettings()), {
    headers: { "cache-control": "no-store" },
  });
}
