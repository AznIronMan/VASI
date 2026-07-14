import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import type { EngineErrorResponse } from "@/lib/evidence-types";
import type { ExternalMediaDescriptor } from "@/lib/owner-types";
import { authorizeParticipantHeaders } from "@/lib/participant-access";

type OpenMedia = {
  activityId: string;
  descriptor: ExternalMediaDescriptor;
  descriptorHash: string;
  openedAt: string;
};

export async function GET(request: Request, {
  params,
}: {
  params: Promise<{ activityId: string; handle: string }>;
}) {
  const authorization = await authorizeParticipantHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const { activityId, handle } = await params;
  if (!/^[A-Za-z0-9_-]{43}$/.test(handle) || !/^[a-z][a-z0-9_-]{0,63}$/.test(activityId)) {
    return new Response(null, { status: 404 });
  }
  const result = await requestEngineAction<OpenMedia | EngineErrorResponse>(
    await buildEngineActor(authorization.session, request.headers),
    { body: { activityId, handle }, method: "POST", path: "/v1/participant/media-open" },
  );
  if (result.status !== 200 || !result.body || !("descriptor" in result.body)) {
    return new Response(null, { status: result.status === 410 ? 410 : 404 });
  }
  const descriptor = result.body.descriptor;
  if (!descriptor.embedUrl || !["generic_embed", "version_aware_preview"].includes(descriptor.capability || "")) {
    return new Response(null, { status: 404 });
  }
  const embed = allowedEmbedURL(descriptor);
  if (!embed) return new Response(null, { status: 404 });
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const html = frameDocument({
    activityId,
    descriptor,
    embed,
    nonce,
  });
  return new Response(html, {
    headers: {
      "cache-control": "private, no-store, max-age=0",
      "content-security-policy": [
        "default-src 'none'",
        `frame-src ${embed.origin}`,
        `script-src 'nonce-${nonce}'`,
        `style-src 'nonce-${nonce}'`,
        "img-src data:",
        "connect-src 'none'",
        "font-src 'none'",
        "media-src 'none'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'self'",
      ].join("; "),
      "content-type": "text/html; charset=utf-8",
      "cross-origin-resource-policy": "same-origin",
      "permissions-policy": "camera=(), microphone=(), geolocation=(), browsing-topics=()",
      "referrer-policy": "strict-origin",
      "x-content-type-options": "nosniff",
      "x-frame-options": "SAMEORIGIN",
    },
    status: 200,
  });
}

function allowedEmbedURL(descriptor: ExternalMediaDescriptor) {
  try {
    const embed = new URL(descriptor.embedUrl || "");
    const origins = descriptor.allowedOrigins || [];
    if (embed.protocol !== "https:" || !origins.includes(embed.origin)) return undefined;
    return embed;
  } catch {
    return undefined;
  }
}

function frameDocument({ activityId, descriptor, embed, nonce }: {
  activityId: string;
  descriptor: ExternalMediaDescriptor;
  embed: URL;
  nonce: string;
}) {
  const message = JSON.stringify({
    activityId,
    descriptorId: descriptor.id,
    itemId: descriptor.itemId,
    schema: "vasi-media-frame/v1",
  }).replaceAll("<", "\\u003c");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHTML(descriptor.title)}</title>
<style nonce="${nonce}">html,body,iframe{border:0;height:100%;margin:0;padding:0;width:100%}body{background:#f2f6f4}iframe{display:block}</style>
</head>
<body>
<iframe id="provider-frame" src="${escapeHTML(embed.href)}" title="${escapeHTML(descriptor.title)}" loading="eager" referrerpolicy="strict-origin" sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-presentation" allow="fullscreen; encrypted-media; picture-in-picture"></iframe>
<script nonce="${nonce}">
"use strict";
const context=${message};
const frame=document.getElementById("provider-frame");
const report=(type,detail)=>parent.postMessage({...context,type,detail},location.origin);
frame.addEventListener("load",()=>report("frame_loaded"));
frame.addEventListener("error",()=>report("frame_error",{code:"provider_frame_load_error"}));
</script>
</body>
</html>`;
}

function escapeHTML(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
