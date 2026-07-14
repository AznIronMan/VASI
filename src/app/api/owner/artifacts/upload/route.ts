import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import { authorizeOwnerMutation } from "@/lib/owner-access";
import type { OwnerArtifact } from "@/lib/owner-types";

const GATEWAY_MAX_BYTES = 26_214_400;
const CHUNK_BYTES = 262_144;

export async function POST(request: Request) {
  const authorization = await authorizeOwnerMutation(request);
  if (!authorization.ok) return authorization.response;
  const tenantId = request.headers.get("x-vasi-tenant-id") || "";
  const encodedFilename = request.headers.get("x-vasi-filename") || "";
  const mediaType = request.headers.get("content-type") || "";
  const expectedByteLength = Number(request.headers.get("content-length"));
  const replacesArtifactId = request.headers.get("x-vasi-replaces-artifact-id") || undefined;
  const sourceArtifactId = request.headers.get("x-vasi-source-artifact-id") || undefined;
  const role = request.headers.get("x-vasi-artifact-role") || "source_document";
  let originalFilename = "";
  try {
    originalFilename = decodeURIComponent(encodedFilename);
  } catch {
    return Response.json({ error: "The document filename is invalid." }, { status: 400 });
  }
  if (!request.body || !Number.isSafeInteger(expectedByteLength) || expectedByteLength < 1 || expectedByteLength > GATEWAY_MAX_BYTES) {
    return Response.json({ error: "The document must be between 1 byte and 25 MiB." }, { status: 413 });
  }
  const actor = await buildEngineActor(authorization.session, request.headers);
  const created = await requestEngineAction<OwnerArtifact>(actor, {
    body: {
      expectedByteLength,
      mediaType,
      originalFilename,
      replacesArtifactId,
      role,
      sourceArtifactId,
      tenantId,
    },
    method: "POST",
    path: "/v1/owner/artifacts",
  });
  if (created.status !== 200 || !created.body) return gatewayEngineResponse(created);
  const artifactId = created.body.id;
  try {
    const reader = request.body.getReader();
    let pending = Buffer.alloc(0);
    let sequence = 0;
    let received = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (value?.length) {
        received += value.length;
        if (received > expectedByteLength) throw new UploadError("The document exceeded its declared size.", 413);
        pending = Buffer.concat([pending, value]);
      }
      while (pending.length >= CHUNK_BYTES || (done && pending.length)) {
        const length = pending.length >= CHUNK_BYTES ? CHUNK_BYTES : pending.length;
        const bytes = pending.subarray(0, length);
        pending = pending.subarray(length);
        const appended = await requestEngineAction(actor, {
          body: { artifactId, data: bytes.toString("base64"), sequence, tenantId },
          method: "POST",
          path: "/v1/owner/artifact-chunks",
        });
        if (appended.status !== 200) throw new UploadError("A document chunk was rejected.", appended.status);
        sequence += 1;
      }
      if (done) break;
    }
    if (received !== expectedByteLength) throw new UploadError("The document length did not match its upload declaration.", 422);
    const finalized = await requestEngineAction<OwnerArtifact>(actor, {
      body: { artifactId, tenantId },
      method: "POST",
      path: "/v1/owner/artifact-finalizations",
    });
    return gatewayEngineResponse(finalized);
  } catch (error) {
    await requestEngineAction(actor, {
      body: { artifactId, tenantId },
      method: "POST",
      path: "/v1/owner/artifact-aborts",
    }).catch(() => undefined);
    const status = error instanceof UploadError ? error.status : 502;
    return Response.json({ error: error instanceof Error ? error.message : "The document upload failed." }, { status });
  }
}

class UploadError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}
