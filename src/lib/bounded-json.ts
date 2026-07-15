export const GATEWAY_JSON_MAXIMUM_BYTES = 65_536;

type BoundedJSONObjectResult =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; response: Response };

type BoundedRequestResult =
  | { ok: true; request: Request }
  | { ok: false; response: Response };

class BoundedBodyError extends Error {
  constructor(readonly code: "invalid_request" | "request_too_large") {
    super(code);
  }
}

export async function boundedJSONObject(
  request: Request,
  maximumBytes = GATEWAY_JSON_MAXIMUM_BYTES,
): Promise<BoundedJSONObjectResult> {
  try {
    return { ok: true, value: await readBoundedJSONObject(request, maximumBytes) };
  } catch (error) {
    return { ok: false, response: boundedBodyErrorResponse(error) };
  }
}

export async function boundedRequestBody(
  request: Request,
  maximumBytes = GATEWAY_JSON_MAXIMUM_BYTES,
): Promise<BoundedRequestResult> {
  try {
    const bytes = await readBoundedBody(request, maximumBytes);
    const headers = new Headers(request.headers);
    headers.delete("content-length");
    return {
      ok: true,
      request: new Request(request, {
        body: bytes.byteLength ? bytes : null,
        duplex: "half",
        headers,
      } as RequestInit),
    };
  } catch (error) {
    return { ok: false, response: boundedBodyErrorResponse(error) };
  }
}

function boundedBodyErrorResponse(error: unknown): Response {
  const result = boundedBodyError(error);
  return Response.json(
    { error: result.error },
    {
      headers: {
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      },
      status: result.status,
    },
  );
}

function boundedBodyError(error: unknown) {
  const tooLarge = error instanceof BoundedBodyError && error.code === "request_too_large";
  return {
    error: tooLarge ? "The request body is too large." : "Invalid request.",
    status: tooLarge ? 413 : 400,
  } as const;
}

async function readBoundedBody(request: Request, maximumBytes: number) {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 2 || maximumBytes > 1_048_576) {
    throw new Error("The gateway request limit is invalid.");
  }

  const advertisedLength = request.headers.get("content-length");
  let expectedLength: number | undefined;
  if (advertisedLength !== null) {
    const normalized = advertisedLength.trim();
    if (!/^\d{1,16}$/.test(normalized)) throw new BoundedBodyError("invalid_request");
    expectedLength = Number(normalized);
    if (!Number.isSafeInteger(expectedLength)) throw new BoundedBodyError("invalid_request");
    if (expectedLength > maximumBytes) throw new BoundedBodyError("request_too_large");
  }

  if (!request.body) {
    if (expectedLength) throw new BoundedBodyError("invalid_request");
    return new Uint8Array();
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new BoundedBodyError("invalid_request");
      length += value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel().catch(() => undefined);
        throw new BoundedBodyError("request_too_large");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof BoundedBodyError) throw error;
    throw new BoundedBodyError("invalid_request");
  } finally {
    reader.releaseLock();
  }

  if (expectedLength !== undefined && expectedLength !== length) {
    throw new BoundedBodyError("invalid_request");
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

export async function readBoundedJSONObject(
  request: Request,
  maximumBytes = GATEWAY_JSON_MAXIMUM_BYTES,
) {
  const bytes = await readBoundedBody(request, maximumBytes);
  if (!bytes.byteLength) throw new BoundedBodyError("invalid_request");

  let value: unknown;
  try {
    const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    value = JSON.parse(source);
  } catch {
    throw new BoundedBodyError("invalid_request");
  }
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new BoundedBodyError("invalid_request");
  }
  return value as Record<string, unknown>;
}
