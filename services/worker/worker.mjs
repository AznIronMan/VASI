import {
  createSettingsPool,
  loadBootstrapSettings,
  readRuntimeSettings,
} from "../../scripts/settings-core.mjs";

const ENGINE_VERSION = "0.4.0";
const bootstrap = loadBootstrapSettings();
const settings = await readRuntimeSettings({ bootstrap, scope: "engine" });
const database = createSettingsPool(bootstrap);
const pollMilliseconds = boundedPollMilliseconds(settings.ENGINE_WORKER_POLL_MS);
let stopping = false;

console.info(`VASI worker ${ENGINE_VERSION} started with the PostgreSQL outbox baseline.`);
while (!stopping) {
  try {
    await database.query(
      'delete from "vasi_engine"."actor_assertion_replay" where "expiresAt" < CURRENT_TIMESTAMP',
    );
    await database.query(
      `select "id" from "vasi_engine"."outbox_job"
       where "status" = 'pending' and "availableAt" <= CURRENT_TIMESTAMP
       order by "availableAt", "createdAt" limit 1`,
    );
  } catch {
    console.error("VASI worker poll failed", "database_unavailable");
  }
  await delay(pollMilliseconds);
}
await database.end();

function boundedPollMilliseconds(value) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1_000 || parsed > 60_000) {
    throw new Error("ENGINE_WORKER_POLL_MS must be between 1000 and 60000.");
  }
  return parsed;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

process.on("SIGINT", () => {
  stopping = true;
});
process.on("SIGTERM", () => {
  stopping = true;
});
