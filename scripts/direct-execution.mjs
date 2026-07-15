import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MAXIMUM_ENTRYPOINT_BYTES = 4_096;

export function isDirectExecution(moduleURL, invocationPath) {
  if (
    typeof moduleURL !== "string" || typeof invocationPath !== "string" ||
    !invocationPath || Buffer.byteLength(invocationPath) > MAXIMUM_ENTRYPOINT_BYTES ||
    invocationPath.includes("\0")
  ) return false;

  try {
    const modulePath = fileURLToPath(moduleURL);
    if (!path.isAbsolute(modulePath)) return false;
    return realpathSync(modulePath) === realpathSync(path.resolve(invocationPath));
  } catch {
    return false;
  }
}
