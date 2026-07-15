import { createCipheriv, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";

import { resolveRuntimeSettingValues } from "@/lib/runtime-settings";
import { runtimeSettingAAD } from "@/lib/settings-crypto";

const installationId = "4af8f8bf-3109-45c6-91fa-273257a321d8";
const settingsKey = Buffer.alloc(32, 3);

describe("runtime settings", () => {
  it("decrypts required values and applies portable defaults", () => {
    const rows = Object.entries({
      BETTER_AUTH_SECRET: "a-secure-runtime-secret-that-is-long-enough",
      BETTER_AUTH_URL: "https://vsign.example.com",
      VASI_ADMIN_EMAILS: "admin@example.com",
      VASI_ADMIN_ORIGIN: "https://vasi.internal.example",
    }).map(([name, value]) => encryptedRow(name, value));

    const settings = resolveRuntimeSettingValues(rows, { installationId, settingsKey });

    expect(settings.BETTER_AUTH_URL).toBe("https://vsign.example.com");
    expect(settings.MICROSOFT_TENANT_ID).toBe("common");
    expect(settings.APPLE_LOGIN_ENABLED).toBe("false");
    expect(settings.SMTP_PORT).toBe("587");
    expect(settings.VASI_TRUSTED_PROXY_CIDRS).toBe("");
  });

  it("fails closed when required installation settings are missing", () => {
    expect(() =>
      resolveRuntimeSettingValues([], { installationId, settingsKey }),
    ).toThrow("Required VASI runtime settings are missing");
  });
});

function encryptedRow(name: string, value: string) {
  const scope = "gateway";
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", settingsKey, iv);
  cipher.setAAD(runtimeSettingAAD({ installationId, name, scope }));
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    authTag: cipher.getAuthTag(),
    ciphertext,
    iv,
    name,
    scope,
  };
}
