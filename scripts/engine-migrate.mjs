import { runEngineMigrations } from "./engine-migrations.mjs";

const applied = await runEngineMigrations();
if (applied.length) {
  console.info(`Applied ${applied.length} VASI engine database migration(s).`);
} else {
  console.info("VASI engine database migrations are current.");
}
