import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const sourcePath = fileURLToPath(new URL("./activity-interaction-recorder.tsx", import.meta.url));

describe("participant activity-interaction recorder privacy boundary", () => {
  it("emits only fixed coarse event types and never reads interaction detail", async () => {
    const source = await readFile(sourcePath, "utf8");
    expect(source).toContain('"presented" | "visible" | "hidden" | "focus" | "blur"');
    expect(source).toContain('"heartbeat" | "interaction" | "disconnect"');
    expect(source).not.toMatch(/\.key\b|clientX|clientY|screenX|screenY|offsetX|offsetY/);
    expect(source).not.toMatch(/navigator\.plugins|clipboard|target\.value|currentTarget\.value/);
    expect(source).not.toMatch(/getUserMedia|enumerateDevices|canvas\.toDataURL/);
  });

  it("keeps synchronization best effort and preserves participant submission", async () => {
    const recorder = await readFile(sourcePath, "utf8");
    const participant = await readFile(
      fileURLToPath(new URL("./participant-request.tsx", import.meta.url)),
      "utf8",
    );
    expect(recorder).toContain("Activity-presence evidence could not be synchronized yet; VASI will retry.");
    expect(participant).toContain("Your response can still be submitted.");
    expect(participant).toContain('fetch("/api/evidence/respond"');
  });
});
