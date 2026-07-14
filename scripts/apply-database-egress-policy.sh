#!/bin/sh
set -eu

DATABASE_CHAIN=VASI_DATABASE_EGRESS
INGRESS_CHAIN=VASI_INGRESS_EGRESS
PROJECT_NAME=vasi-engine

ACTION=apply
if [ "${1:-}" = "apply" ] || [ "${1:-}" = "remove" ]; then
  ACTION=$1
  shift
fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --chain|--database-chain)
      [ "$#" -ge 2 ] || { printf '%s\n' "VASI database egress policy arguments are invalid." >&2; exit 1; }
      DATABASE_CHAIN=$2
      shift 2
      ;;
    --ingress-chain)
      [ "$#" -ge 2 ] || { printf '%s\n' "VASI database egress policy arguments are invalid." >&2; exit 1; }
      INGRESS_CHAIN=$2
      shift 2
      ;;
    --project-name)
      [ "$#" -ge 2 ] || { printf '%s\n' "VASI database egress policy arguments are invalid." >&2; exit 1; }
      PROJECT_NAME=$2
      shift 2
      ;;
    *)
      printf '%s\n' "Usage: apply-database-egress-policy.sh [apply|remove] [--project-name NAME] [--database-chain CHAIN] [--ingress-chain CHAIN]" >&2
      exit 1
      ;;
  esac
done
case "$PROJECT_NAME" in
  ""|[!a-z0-9]*|*[!a-z0-9_-]*)
    printf '%s\n' "VASI database egress policy arguments are invalid." >&2
    exit 1
    ;;
esac
for CHAIN in "$DATABASE_CHAIN" "$INGRESS_CHAIN"; do
  case "$CHAIN" in
    ""|[!A-Z]*|*[!A-Z0-9_]*)
      printf '%s\n' "VASI database egress policy arguments are invalid." >&2
      exit 1
      ;;
  esac
  if [ "${#CHAIN}" -gt 28 ]; then
    printf '%s\n' "VASI database egress policy arguments are invalid." >&2
    exit 1
  fi
done
if [ "${#PROJECT_NAME}" -gt 64 ] || [ "$DATABASE_CHAIN" = "$INGRESS_CHAIN" ]; then
  printf '%s\n' "VASI database egress policy arguments are invalid." >&2
  exit 1
fi
DATABASE_NETWORK=${PROJECT_NAME}_database-egress
INGRESS_NETWORK=${PROJECT_NAME}_private-ingress-listener

if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' "VASI database egress policy requires root." >&2
  exit 1
fi

if [ "$ACTION" = "remove" ]; then
  for CHAIN in "$DATABASE_CHAIN" "$INGRESS_CHAIN"; do
    while iptables -w 10 -C DOCKER-USER -j "$CHAIN" >/dev/null 2>&1; do
      iptables -w 10 -D DOCKER-USER -j "$CHAIN" >/dev/null 2>&1
    done
    if iptables -w 10 -S "$CHAIN" >/dev/null 2>&1; then
      iptables -w 10 -F "$CHAIN" >/dev/null 2>&1
      iptables -w 10 -X "$CHAIN" >/dev/null 2>&1
    fi
  done
  printf '%s\n' "VASI engine egress policy removed."
  exit 0
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$ROOT"
DATABASE_SUBNET=$(docker network inspect "$DATABASE_NETWORK" --format '{{(index .IPAM.Config 0).Subnet}}')
INGRESS_SUBNET=$(docker network inspect "$INGRESS_NETWORK" --format '{{(index .IPAM.Config 0).Subnet}}')
DATABASE_TEMPORARY=$(mktemp /run/vasi-database-egress-policy.XXXXXX)
INGRESS_TEMPORARY=
trap 'rm -f "$DATABASE_TEMPORARY" "$INGRESS_TEMPORARY"' EXIT HUP INT TERM
INGRESS_TEMPORARY=$(mktemp /run/vasi-private-ingress-egress-policy.XXXXXX)
chmod 0600 "$DATABASE_TEMPORARY" "$INGRESS_TEMPORARY"

if [ -f compose.live.yaml ]; then
  docker compose --project-name "$PROJECT_NAME" -f compose.engine.yaml -f compose.live.yaml \
    --profile tools run --rm --no-deps egress-policy \
    --subnet "$DATABASE_SUBNET" --chain "$DATABASE_CHAIN" >"$DATABASE_TEMPORARY"
  docker compose --project-name "$PROJECT_NAME" -f compose.engine.yaml -f compose.live.yaml \
    --profile tools run --rm --no-deps --entrypoint node egress-policy \
    scripts/render-private-ingress-egress-policy.mjs \
    --subnet "$INGRESS_SUBNET" --chain "$INGRESS_CHAIN" >"$INGRESS_TEMPORARY"
else
  docker compose --project-name "$PROJECT_NAME" -f compose.engine.yaml --profile tools \
    run --rm --no-deps egress-policy --subnet "$DATABASE_SUBNET" \
    --chain "$DATABASE_CHAIN" >"$DATABASE_TEMPORARY"
  docker compose --project-name "$PROJECT_NAME" -f compose.engine.yaml --profile tools \
    run --rm --no-deps --entrypoint node egress-policy \
    scripts/render-private-ingress-egress-policy.mjs \
    --subnet "$INGRESS_SUBNET" --chain "$INGRESS_CHAIN" >"$INGRESS_TEMPORARY"
fi
if [ ! -s "$DATABASE_TEMPORARY" ] || [ ! -s "$INGRESS_TEMPORARY" ]; then
  printf '%s\n' "VASI engine egress policy validation failed." >&2
  exit 1
fi

iptables -w 10 -N "$DATABASE_CHAIN" >/dev/null 2>&1 || true
iptables -w 10 -N "$INGRESS_CHAIN" >/dev/null 2>&1 || true
if ! iptables-restore --test --noflush <"$DATABASE_TEMPORARY" 2>/dev/null ||
   ! iptables-restore --test --noflush <"$INGRESS_TEMPORARY" 2>/dev/null; then
  printf '%s\n' "VASI engine egress policy validation failed." >&2
  exit 1
fi
if ! iptables-restore --noflush <"$DATABASE_TEMPORARY" 2>/dev/null ||
   ! iptables-restore --noflush <"$INGRESS_TEMPORARY" 2>/dev/null; then
  printf '%s\n' "VASI engine egress policy application failed." >&2
  exit 1
fi
for CHAIN in "$DATABASE_CHAIN" "$INGRESS_CHAIN"; do
  if ! iptables -w 10 -C DOCKER-USER -j "$CHAIN" >/dev/null 2>&1; then
    if ! iptables -w 10 -I DOCKER-USER 1 -j "$CHAIN" >/dev/null 2>&1; then
      printf '%s\n' "VASI engine egress policy application failed." >&2
      exit 1
    fi
  fi
done
printf '%s\n' "VASI engine egress policy applied."
