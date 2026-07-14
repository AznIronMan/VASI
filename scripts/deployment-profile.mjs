import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { validateInstallationProfile } from "../packages/engine-domain/productization.mjs";

const name = process.argv[2];
if (!['self-hosted', 'saas'].includes(name)) {
  console.error("Usage: node scripts/deployment-profile.mjs self-hosted|saas");
  process.exitCode = 1;
} else {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const source = await readFile(path.join(root, "config", "deployment-profiles", `${name}.json`), "utf8");
  console.info(JSON.stringify(validateInstallationProfile(JSON.parse(source)), null, 2));
}
