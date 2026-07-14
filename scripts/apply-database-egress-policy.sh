#!/bin/sh
set -eu

CHAIN=VASI_DATABASE_EGRESS
PROJECT_NAME=vasi-engine

ACTION=apply
if [ "${1:-}" = "apply" ] || [ "${1:-}" = "remove" ]; then
  ACTION=$1
  shift
fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --chain)
      [ "$#" -ge 2 ] || { printf '%s\n' "VASI database egress policy arguments are invalid." >&2; exit 1; }
      CHAIN=$2
      shift 2
      ;;
    --project-name)
      [ "$#" -ge 2 ] || { printf '%s\n' "VASI database egress policy arguments are invalid." >&2; exit 1; }
      PROJECT_NAME=$2
      shift 2
      ;;
    *)
      printf '%s\n' "Usage: apply-database-egress-policy.sh [apply|remove] [--project-name NAME] [--chain CHAIN]" >&2
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
case "$CHAIN" in
  ""|[!A-Z]*|*[!A-Z0-9_]*)
    printf '%s\n' "VASI database egress policy arguments are invalid." >&2
    exit 1
    ;;
esac
if [ "${#PROJECT_NAME}" -gt 64 ] || [ "${#CHAIN}" -gt 28 ]; then
  printf '%s\n' "VASI database egress policy arguments are invalid." >&2
  exit 1
fi
PROJECT_NETWORK=${PROJECT_NAME}_database-egress

if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' "VASI database egress policy requires root." >&2
  exit 1
fi

if [ "$ACTION" = "remove" ]; then
  while iptables -w 10 -C DOCKER-USER -j "$CHAIN" >/dev/null 2>&1; do
    iptables -w 10 -D DOCKER-USER -j "$CHAIN" >/dev/null 2>&1
  done
  if iptables -w 10 -S "$CHAIN" >/dev/null 2>&1; then
    iptables -w 10 -F "$CHAIN" >/dev/null 2>&1
    iptables -w 10 -X "$CHAIN" >/dev/null 2>&1
  fi
  printf '%s\n' "VASI database egress policy removed."
  exit 0
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$ROOT"
SUBNET=$(docker network inspect "$PROJECT_NETWORK" --format '{{(index .IPAM.Config 0).Subnet}}')
TEMPORARY=$(mktemp /run/vasi-database-egress-policy.XXXXXX)
trap 'rm -f "$TEMPORARY"' EXIT HUP INT TERM
chmod 0600 "$TEMPORARY"

if [ -f compose.live.yaml ]; then
  docker compose --project-name "$PROJECT_NAME" -f compose.engine.yaml -f compose.live.yaml \
    --profile tools run --rm --no-deps egress-policy \
    --subnet "$SUBNET" --chain "$CHAIN" >"$TEMPORARY"
else
  docker compose --project-name "$PROJECT_NAME" -f compose.engine.yaml --profile tools \
    run --rm --no-deps egress-policy --subnet "$SUBNET" --chain "$CHAIN" >"$TEMPORARY"
fi
if [ ! -s "$TEMPORARY" ]; then
  printf '%s\n' "VASI database egress policy validation failed." >&2
  exit 1
fi

iptables -w 10 -N "$CHAIN" >/dev/null 2>&1 || true
if ! iptables-restore --test --noflush <"$TEMPORARY" 2>/dev/null; then
  printf '%s\n' "VASI database egress policy validation failed." >&2
  exit 1
fi
if ! iptables-restore --noflush <"$TEMPORARY" 2>/dev/null; then
  printf '%s\n' "VASI database egress policy application failed." >&2
  exit 1
fi
if ! iptables -w 10 -C DOCKER-USER -j "$CHAIN" >/dev/null 2>&1; then
  if ! iptables -w 10 -I DOCKER-USER 1 -j "$CHAIN" >/dev/null 2>&1; then
    printf '%s\n' "VASI database egress policy application failed." >&2
    exit 1
  fi
fi
printf '%s\n' "VASI database egress policy applied."
