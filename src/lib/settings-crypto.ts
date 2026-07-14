import { createDecipheriv } from "node:crypto";

export type EncryptedRuntimeSetting = {
  authTag: Buffer;
  ciphertext: Buffer;
  iv: Buffer;
  name: string;
  scope: string;
};

export function runtimeSettingAAD({
  installationId,
  name,
  scope,
}: {
  installationId: string;
  name: string;
  scope: string;
}) {
  return Buffer.from(
    ["vasi-runtime-setting-v1", installationId, scope, name].join("\0"),
    "utf8",
  );
}

export function decryptRuntimeSetting(
  setting: EncryptedRuntimeSetting,
  installationId: string,
  settingsKey: Buffer,
) {
  if (settingsKey.length !== 32 || setting.iv.length !== 12 || setting.authTag.length !== 16) {
    throw new Error(`Runtime setting ${setting.name} has invalid encryption material.`);
  }

  try {
    const decipher = createDecipheriv("aes-256-gcm", settingsKey, setting.iv);
    decipher.setAAD(
      runtimeSettingAAD({ installationId, name: setting.name, scope: setting.scope }),
    );
    decipher.setAuthTag(setting.authTag);
    return Buffer.concat([decipher.update(setting.ciphertext), decipher.final()]).toString(
      "utf8",
    );
  } catch {
    throw new Error(`Runtime setting ${setting.name} could not be authenticated.`);
  }
}
