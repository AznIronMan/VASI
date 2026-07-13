#!/usr/bin/env bash

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this isolated restore helper as root on the PostgreSQL host." >&2
  exit 1
fi

dump_path="${1:-}"
target_db="restorecheck_VASI_app"
work_db="${target_db}_work"
application_role="VASI"

if [[ ! -r "$dump_path" || "$(basename "$dump_path")" != "VASI.dump" ]]; then
  echo "Usage: $0 /protected/backup-directory/VASI.dump" >&2
  exit 2
fi

pg_as_postgres() {
  runuser -u postgres -- "$@"
}

cleanup() {
  pg_as_postgres dropdb --if-exists --force "$work_db" >/dev/null 2>&1 || true
}

trap cleanup EXIT HUP INT TERM

pg_restore --list "$dump_path" >/dev/null
pg_as_postgres dropdb --if-exists --force "$work_db" >/dev/null 2>&1 || true
pg_as_postgres createdb -T template0 -O "$application_role" "$work_db"

pg_as_postgres pg_restore \
  --exit-on-error \
  --single-transaction \
  --no-owner \
  --no-acl \
  --no-publications \
  --no-subscriptions \
  --role="$application_role" \
  -d "$work_db" \
  "$dump_path"

pg_as_postgres psql -v ON_ERROR_STOP=1 -d "$work_db" -c \
  "set role \"$application_role\"; select count(*) from public.\"_prisma_migrations\";" >/dev/null

pg_as_postgres dropdb --if-exists --force "$target_db" >/dev/null 2>&1 || true
pg_as_postgres psql -v ON_ERROR_STOP=1 -d postgres -c \
  "alter database \"$work_db\" rename to \"$target_db\";" >/dev/null

trap - EXIT HUP INT TERM
echo "Restored VASI into isolated application-owned database $target_db."
