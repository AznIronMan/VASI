#!/bin/sh

# Shared, source-only helpers for the two root-owned edge assurance services.
# The calling script is responsible for set -eu and umask 077.

edge_fail() {
  echo "VASI public-edge assurance failed closed." >&2
  exit 1
}

edge_require_command() {
  command -v "$1" >/dev/null 2>&1 || edge_fail
}

edge_require_runtime() {
  [ "$(id -u)" -eq 0 ] || edge_fail
  for edge_command in docker flock install jq readlink stat; do
    edge_require_command "$edge_command"
  done
  EDGE_SOURCE_ROOT=$(pwd -P)
  [ -f "$EDGE_SOURCE_ROOT/package.json" ] || edge_fail
  [ -f "$EDGE_SOURCE_ROOT/config/edge-monitor-policy.json" ] || edge_fail
}

edge_load_policy() {
  EDGE_AUDITOR_IMAGE=$(jq -er '
    select(.schema == "vasi-edge-monitor-policy/v1") |
    .auditorImage | strings | select(test("@sha256:[a-f0-9]{64}$"))
  ' "$EDGE_SOURCE_ROOT/config/edge-monitor-policy.json") || edge_fail
  EDGE_SCANNER_IMAGE=$(jq -er '
    select(.schema == "vasi-edge-monitor-policy/v1") |
    .scannerImage | strings | select(test("@sha256:[a-f0-9]{64}$"))
  ' "$EDGE_SOURCE_ROOT/config/edge-monitor-policy.json") || edge_fail
}

edge_require_local_image() {
  docker image inspect "$1" >/dev/null 2>&1 || edge_fail
}

edge_validate_configuration_file() {
  EDGE_CONFIGURATION_FILE=$1
  case "$EDGE_CONFIGURATION_FILE" in
    /var/lib/vasi-edge/*.json) ;;
    *) edge_fail ;;
  esac
  [ -f "$EDGE_CONFIGURATION_FILE" ] || edge_fail
  [ ! -L "$EDGE_CONFIGURATION_FILE" ] || edge_fail
  [ "$(readlink -f -- "$EDGE_CONFIGURATION_FILE")" = "$EDGE_CONFIGURATION_FILE" ] || edge_fail
  [ "$(stat -c %u -- "$EDGE_CONFIGURATION_FILE")" = "0" ] || edge_fail
  [ "$(stat -c %a -- "$EDGE_CONFIGURATION_FILE")" = "600" ] || edge_fail
  edge_configuration_bytes=$(stat -c %s -- "$EDGE_CONFIGURATION_FILE") || edge_fail
  [ "$edge_configuration_bytes" -ge 2 ] || edge_fail
  [ "$edge_configuration_bytes" -le 65536 ] || edge_fail
}

edge_load_configuration() {
  edge_validate_configuration_file "$1"
  EDGE_CONFIGURATION=$(docker run --rm --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --pids-limit 128 --memory 128m --cpus 1 \
    --user 0:0 \
    -v "$EDGE_SOURCE_ROOT:/opt/vasi:ro" \
    -v "$EDGE_CONFIGURATION_FILE:/run/vasi-edge/monitor.json:ro" \
    -w /opt/vasi \
    "$EDGE_AUDITOR_IMAGE" node scripts/edge-monitor-contract.mjs \
    validate-config /run/vasi-edge/monitor.json) || edge_fail
  printf '%s' "$EDGE_CONFIGURATION" | jq -e . >/dev/null 2>&1 || edge_fail

  EDGE_LIVE_CONTAINER=$(printf '%s' "$EDGE_CONFIGURATION" | jq -er '.liveContainer') || edge_fail
  EDGE_ROLLBACK_CONTAINER=$(printf '%s' "$EDGE_CONFIGURATION" | jq -er '.rollbackContainer') || edge_fail
  EDGE_IMAGE_REFERENCE=$(printf '%s' "$EDGE_CONFIGURATION" | jq -er '.imageReference') || edge_fail
  EDGE_PUBLIC_HOST=$(printf '%s' "$EDGE_CONFIGURATION" | jq -er '.publicHost') || edge_fail
  EDGE_RETIRED_HOST=$(printf '%s' "$EDGE_CONFIGURATION" | jq -er '.retiredHost') || edge_fail
  EDGE_GATEWAY_UPSTREAM=$(printf '%s' "$EDGE_CONFIGURATION" | jq -er '.gatewayUpstreamName') || edge_fail
  EDGE_LISTENER_PORTS=$(printf '%s' "$EDGE_CONFIGURATION" | jq -er '.listenerPorts | map(tostring) | join(" ")') || edge_fail
  EDGE_SCAN_ROOT=$(printf '%s' "$EDGE_CONFIGURATION" | jq -er '.scanRoot') || edge_fail
  EDGE_SCANNER_CACHE=$(printf '%s' "$EDGE_CONFIGURATION" | jq -er '.scannerCache') || edge_fail
  EDGE_RETAINED_SCANS=$(printf '%s' "$EDGE_CONFIGURATION" | jq -er '.retainedScans') || edge_fail
}

edge_take_lock() {
  install -d -o root -g root -m 0755 /run/lock
  exec 9>/run/lock/vasi-edge-monitor.lock
  flock -n 9 || edge_fail
}

edge_protect_directory() {
  edge_directory=$1
  edge_prefix=$2
  case "$edge_directory" in
    "$edge_prefix"/*) ;;
    *) edge_fail ;;
  esac
  install -d -o root -g root -m 0700 "$edge_prefix"
  [ ! -L "$edge_prefix" ] || edge_fail
  [ "$(readlink -f -- "$edge_prefix")" = "$edge_prefix" ] || edge_fail
  install -d -o root -g root -m 0700 "$edge_directory"
  [ ! -L "$edge_directory" ] || edge_fail
  [ "$(readlink -f -- "$edge_directory")" = "$edge_directory" ] || edge_fail
  chown root:root "$edge_prefix" "$edge_directory"
  chmod 0700 "$edge_prefix" "$edge_directory"
}

edge_assert_live_container() {
  edge_live_inspection=$(docker inspect --type container "$EDGE_LIVE_CONTAINER" 2>/dev/null) || edge_fail
  printf '%s' "$edge_live_inspection" | jq -e --arg image "$EDGE_IMAGE_REFERENCE" '
    length == 1 and
    .[0].State.Running == true and
    .[0].Config.Image == $image and
    .[0].HostConfig.RestartPolicy.Name == "always" and
    (.[0].Image | strings | test("^sha256:[a-f0-9]{64}$"))
  ' >/dev/null || edge_fail
  EDGE_LIVE_IMAGE_ID=$(printf '%s' "$edge_live_inspection" | jq -er '.[0].Image') || edge_fail
  edge_configured_image_id=$(docker image inspect "$EDGE_IMAGE_REFERENCE" --format '{{.Id}}' 2>/dev/null) || edge_fail
  [ "$EDGE_LIVE_IMAGE_ID" = "$edge_configured_image_id" ] || edge_fail
}

edge_assert_rollback_container() {
  edge_rollback_inspection=$(docker inspect --type container "$EDGE_ROLLBACK_CONTAINER" 2>/dev/null) || edge_fail
  printf '%s' "$edge_rollback_inspection" | jq -e '
    length == 1 and
    .[0].State.Running == false and
    .[0].HostConfig.RestartPolicy.Name == "no" and
    (.[0].Image | strings | test("^sha256:[a-f0-9]{64}$"))
  ' >/dev/null || edge_fail
}

edge_assert_listener_bindings() {
  edge_live_inspection=$(docker inspect --type container "$EDGE_LIVE_CONTAINER" 2>/dev/null) || edge_fail
  EDGE_LISTENERS_CHECKED=0
  for edge_port in $EDGE_LISTENER_PORTS; do
    printf '%s' "$edge_live_inspection" | jq -e --arg key "$edge_port/tcp" '
      length == 1 and
      (.[0].HostConfig.PortBindings[$key] | type == "array" and length > 0) and
      all(.[0].HostConfig.PortBindings[$key][];
        (.HostPort | strings | test("^[0-9]{1,5}$")) and
        ((.HostPort | tonumber) >= 1) and ((.HostPort | tonumber) <= 65535)
      )
    ' >/dev/null || edge_fail
    EDGE_LISTENERS_CHECKED=$((EDGE_LISTENERS_CHECKED + 1))
  done
}
