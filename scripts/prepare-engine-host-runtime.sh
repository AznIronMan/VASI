#!/bin/sh
set -eu

umask 022
offline=""
if [ "$#" -eq 1 ] && [ "$1" = "--offline" ]; then
  offline="--offline"
elif [ "$#" -ne 0 ]; then
  echo "Usage: /bin/sh scripts/prepare-engine-host-runtime.sh [--offline]" >&2
  exit 64
fi

command -v node >/dev/null 2>&1 || { echo "Node is required." >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "npm is required." >&2; exit 1; }
if [ "$(id -u)" -ne 0 ]; then
  echo "Engine host runtime preparation must run as root." >&2
  exit 1
fi
test -f package.json && test -f package-lock.json || {
  echo "The VASI release manifests are unavailable." >&2
  exit 1
}

NODE_ENV=production npm_config_engine_strict=true npm ci --omit=dev --ignore-scripts --no-audit --no-fund $offline
/usr/bin/install -d -o root -g root -m 0755 /usr/local/libexec/vasi
/usr/bin/install -o root -g root -m 0644 scripts/verify-engine-host-runtime.mjs \
  /usr/local/libexec/vasi/verify-engine-host-runtime.mjs
exec node /usr/local/libexec/vasi/verify-engine-host-runtime.mjs
