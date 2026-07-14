import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("participant context recorder privacy boundary", () => {
  it("uses only disclosed bounded context APIs and excludes invasive fingerprinting", async () => {
    const source = await readFile(
      fileURLToPath(new URL("./participant-context-recorder.tsx", import.meta.url)),
      "utf8",
    );
    expect(source).toContain("vasi-participant-context/v1");
    expect(source).toContain("prefers-reduced-motion");
    expect(source).toContain("maxTouchPoints");
    expect(source).not.toMatch(/\.plugins\b|mimeTypes|AudioContext|hardwareConcurrency|deviceMemory|getBattery/);
    expect(source).not.toMatch(/geolocation|mediaDevices|getUserMedia|enumerateDevices/);
    expect(source).not.toMatch(/canvas|webgl|font|gpu|clientX|clientY|screenX|screenY|key(down|up|press)/i);
  });
});
