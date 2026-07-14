import { createCipheriv, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";

import { decryptRuntimeSetting, runtimeSettingAAD } from "@/lib/settings-crypto";

describe("runtime setting encryption", () => {
  it("decrypts authenticated installation and setting-bound values", () => {
    const installationId = "4af8f8bf-3109-45c6-91fa-273257a321d8";
    const name = "BETTER_AUTH_SECRET";
    const scope = "gateway";
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(runtimeSettingAAD({ installationId, name, scope }));
    const ciphertext = Buffer.concat([cipher.update("private-value", "utf8"), cipher.final()]);

    expect(
      decryptRuntimeSetting(
        { authTag: cipher.getAuthTag(), ciphertext, iv, name, scope },
        installationId,
        key,
      ),
    ).toBe("private-value");
  });

  it("rejects ciphertext moved to another setting name", () => {
    const installationId = "4af8f8bf-3109-45c6-91fa-273257a321d8";
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(
      runtimeSettingAAD({ installationId, name: "SMTP_PASSWORD", scope: "gateway" }),
    );
    const ciphertext = Buffer.concat([cipher.update("private-value", "utf8"), cipher.final()]);

    expect(() =>
      decryptRuntimeSetting(
        {
          authTag: cipher.getAuthTag(),
          ciphertext,
          iv,
          name: "BETTER_AUTH_SECRET",
          scope: "gateway",
        },
        installationId,
        key,
      ),
    ).toThrow("could not be authenticated");
  });
});
