import { runMigrations } from "./migrations.mjs";

const applied = await runMigrations();
if (applied.length) {
  console.info(`Applied ${applied.length} VASI database migration(s).`);
} else {
  console.info("VASI database migrations are current.");
}
