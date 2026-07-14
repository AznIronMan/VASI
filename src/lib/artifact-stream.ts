import { createHash } from "node:crypto";

import { requestEngineAction, type EngineActor } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";

export type StreamableArtifact = {
  activityId?: string;
  byteLength: number;
  chunkCount: number;
  id: string;
  mediaType: string;
  originalFilename: string;
  sha256: string;
};

export type StreamableEvidenceExport = {
  byteLength: number;
  chunkCount: number;
  filename: string;
  id: string;
  mediaType: string;
  sha256: string;
  sourceManifestHash: string;
};

export type StreamableParticipantDataExport = Omit<StreamableEvidenceExport, "sourceManifestHash">;

export async function streamEngineArtifact({
  actor,
  chunkPath,
  openBody,
  openPath,
}: {
  actor: EngineActor;
  chunkPath: string;
  openBody: Record<string, unknown>;
  openPath: string;
}) {
  const opened = await requestEngineAction<StreamableArtifact>(actor, {
    body: openBody,
    method: "POST",
    path: openPath,
  });
  if (opened.status !== 200 || !opened.body) return gatewayEngineResponse(opened);
  const artifact = opened.body;
  let sequence = 0;
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (sequence >= artifact.chunkCount) {
        controller.close();
        return;
      }
      try {
        const chunk = await requestEngineAction<{
          byteLength: number;
          data: string;
          sequence: number;
          sha256: string;
        }>(actor, {
          body: { ...openBody, sequence },
          method: "POST",
          path: chunkPath,
        });
        if (chunk.status !== 200 || !chunk.body || chunk.body.sequence !== sequence) {
          throw new Error("The private artifact stream was interrupted.");
        }
        const bytes = Buffer.from(chunk.body.data, "base64");
        const digest = createHash("sha256").update(bytes).digest("hex");
        if (bytes.length !== chunk.body.byteLength || digest !== chunk.body.sha256) {
          throw new Error("The private artifact chunk failed its integrity check.");
        }
        sequence += 1;
        controller.enqueue(bytes);
      } catch (error) {
        controller.error(error);
      }
    },
  });
  const disposition = openBody.disposition === "attachment" ? "attachment" : "inline";
  const fallback = artifact.originalFilename.replace(/[^A-Za-z0-9._-]/g, "_") || "document";
  return new Response(stream, {
    headers: {
      "cache-control": "private, no-store, max-age=0",
      "content-disposition": `${disposition}; filename="${fallback}"; filename*=UTF-8''${encodeURIComponent(artifact.originalFilename)}`,
      "content-length": String(artifact.byteLength),
      "content-security-policy": "default-src 'none'; sandbox",
      "content-type": artifact.mediaType,
      "referrer-policy": "no-referrer",
      "x-content-sha256": artifact.sha256,
      "x-content-type-options": "nosniff",
    },
    status: 200,
  });
}

export async function streamEngineEvidenceExport({
  actor,
  chunkPath,
  openBody,
  openPath,
}: {
  actor: EngineActor;
  chunkPath: string;
  openBody: Record<string, unknown>;
  openPath: string;
}) {
  const opened = await requestEngineAction<StreamableEvidenceExport>(actor, {
    body: openBody,
    method: "POST",
    path: openPath,
  });
  if (opened.status !== 200 || !opened.body) return gatewayEngineResponse(opened);
  const artifact = opened.body;
  let sequence = 0;
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (sequence >= artifact.chunkCount) {
        controller.close();
        return;
      }
      try {
        const chunk = await requestEngineAction<{
          byteLength: number;
          data: string;
          sequence: number;
          sha256: string;
        }>(actor, {
          body: { exportArtifactId: artifact.id, sequence },
          method: "POST",
          path: chunkPath,
        });
        if (chunk.status !== 200 || !chunk.body || chunk.body.sequence !== sequence) {
          throw new Error("The private evidence export stream was interrupted.");
        }
        const bytes = Buffer.from(chunk.body.data, "base64");
        const digest = createHash("sha256").update(bytes).digest("hex");
        if (bytes.length !== chunk.body.byteLength || digest !== chunk.body.sha256) {
          throw new Error("The private evidence export chunk failed its integrity check.");
        }
        sequence += 1;
        controller.enqueue(bytes);
      } catch (error) {
        controller.error(error);
      }
    },
  });
  const fallback = artifact.filename.replace(/[^A-Za-z0-9._-]/g, "_") || "vasi-evidence";
  return new Response(stream, {
    headers: {
      "cache-control": "private, no-store, max-age=0",
      "content-disposition": `attachment; filename="${fallback}"; filename*=UTF-8''${encodeURIComponent(artifact.filename)}`,
      "content-length": String(artifact.byteLength),
      "content-security-policy": "default-src 'none'; sandbox",
      "content-type": artifact.mediaType,
      "referrer-policy": "no-referrer",
      "x-content-sha256": artifact.sha256,
      "x-content-type-options": "nosniff",
      "x-vasi-manifest-fingerprint": artifact.sourceManifestHash,
    },
    status: 200,
  });
}

export async function streamEngineParticipantDataExport({
  actor,
  requestId,
}: {
  actor: EngineActor;
  requestId: string;
}) {
  const opened = await requestEngineAction<StreamableParticipantDataExport>(actor, {
    body: { requestId },
    method: "POST",
    path: "/v1/participant/data-exports",
  });
  if (opened.status !== 200 || !opened.body) return gatewayEngineResponse(opened);
  const artifact = opened.body;
  let sequence = 0;
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (sequence >= artifact.chunkCount) {
        controller.close();
        return;
      }
      try {
        const chunk = await requestEngineAction<{
          byteLength: number;
          data: string;
          sequence: number;
          sha256: string;
        }>(actor, {
          body: { exportId: artifact.id, requestId, sequence },
          method: "POST",
          path: "/v1/participant/data-export-chunks",
        });
        if (chunk.status !== 200 || !chunk.body || chunk.body.sequence !== sequence) {
          throw new Error("The private participant data stream was interrupted.");
        }
        const bytes = Buffer.from(chunk.body.data, "base64");
        const digest = createHash("sha256").update(bytes).digest("hex");
        if (bytes.length !== chunk.body.byteLength || digest !== chunk.body.sha256) {
          throw new Error("The private participant data chunk failed its integrity check.");
        }
        sequence += 1;
        controller.enqueue(bytes);
      } catch (error) {
        controller.error(error);
      }
    },
  });
  const filename = artifact.filename.replace(/[^A-Za-z0-9._-]/g, "_") || "vasi-my-data.json";
  return new Response(stream, {
    headers: {
      "cache-control": "private, no-store, max-age=0",
      "content-disposition": `attachment; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(artifact.filename)}`,
      "content-length": String(artifact.byteLength),
      "content-security-policy": "default-src 'none'; sandbox",
      "content-type": artifact.mediaType,
      "referrer-policy": "no-referrer",
      "x-content-sha256": artifact.sha256,
      "x-content-type-options": "nosniff",
    },
    status: 200,
  });
}
