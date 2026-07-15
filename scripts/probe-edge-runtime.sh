#!/bin/sh
set -eu
umask 077

. "$(dirname "$0")/edge-monitor-common.sh"

[ "$#" -eq 1 ] || edge_fail
edge_require_runtime
edge_require_command curl
edge_load_policy
edge_require_local_image "$EDGE_AUDITOR_IMAGE"
edge_load_configuration "$1"
edge_take_lock
edge_protect_directory "$EDGE_SCAN_ROOT" /var/lib/vasi-edge
edge_assert_live_container
edge_assert_rollback_container
edge_assert_listener_bindings
edge_runtime_image_id=$EDGE_LIVE_IMAGE_ID

docker exec "$EDGE_LIVE_CONTAINER" nginx -t >/dev/null 2>&1 || edge_fail

edge_temporary_directory=$(mktemp -d /tmp/vasi-edge-runtime.XXXXXX) || edge_fail
edge_cleanup() {
  rm -rf -- "$edge_temporary_directory"
}
trap edge_cleanup EXIT HUP INT TERM

edge_effective_configuration="$edge_temporary_directory/nginx.conf"
docker exec "$EDGE_LIVE_CONTAINER" nginx -T > "$edge_effective_configuration" 2>/dev/null || edge_fail
edge_configuration_bytes=$(stat -c %s -- "$edge_effective_configuration") || edge_fail
[ "$edge_configuration_bytes" -ge 1 ] || edge_fail
[ "$edge_configuration_bytes" -le 4194304 ] || edge_fail
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 128 \
  --memory 128m --cpus 1 --user 0:0 \
  -v "$EDGE_SOURCE_ROOT:/opt/vasi:ro" \
  -v "$edge_effective_configuration:/run/vasi-edge/nginx.conf:ro" \
  -w /opt/vasi \
  "$EDGE_AUDITOR_IMAGE" node scripts/public-ingress-config.mjs audit \
  --config /run/vasi-edge/nginx.conf \
  --public-host "$EDGE_PUBLIC_HOST" \
  --retired-host "$EDGE_RETIRED_HOST" \
  --gateway-upstream-name "$EDGE_GATEWAY_UPSTREAM" >/dev/null || edge_fail

edge_health_body="$edge_temporary_directory/health.json"
edge_health_headers="$edge_temporary_directory/health.headers"
edge_health_status=$(curl --silent --show-error --noproxy '*' \
  --proto '=https' --tlsv1.2 --max-time 10 --max-filesize 65536 \
  --output "$edge_health_body" --dump-header "$edge_health_headers" \
  --write-out '%{http_code}' "https://$EDGE_PUBLIC_HOST/api/health") || edge_fail
[ "$edge_health_status" = "200" ] || edge_fail
EDGE_RELEASE_VERSION=$(jq -er '.version | strings' "$EDGE_SOURCE_ROOT/package.json") || edge_fail
jq -e --arg version "$EDGE_RELEASE_VERSION" '
  .status == "ok" and .service == "vasi-auth" and .version == $version
' "$edge_health_body" >/dev/null || edge_fail
[ "$(stat -c %s -- "$edge_health_headers")" -le 65536 ] || edge_fail
awk 'BEGIN { found=0 } tolower($0) ~ /^cache-control:/ && tolower($0) ~ /no-store/ { found=1 } END { exit(found ? 0 : 1) }' \
  "$edge_health_headers" || edge_fail
awk 'BEGIN { found=0 } tolower($0) ~ /^strict-transport-security:/ { found=1 } END { exit(found ? 0 : 1) }' \
  "$edge_health_headers" || edge_fail
awk 'BEGIN { found=0 } tolower($0) ~ /^x-content-type-options:[[:space:]]*nosniff/ { found=1 } END { exit(found ? 0 : 1) }' \
  "$edge_health_headers" || edge_fail
if awk 'tolower($0) ~ /^server:/ && $0 ~ /\/[0-9]/ { found=1 } END { exit(found ? 0 : 1) }' "$edge_health_headers"; then
  edge_fail
fi

edge_retired_body="$edge_temporary_directory/retired.body"
edge_retired_headers="$edge_temporary_directory/retired.headers"
edge_retired_status=$(curl --silent --show-error --noproxy '*' \
  --proto '=https' --tlsv1.2 --max-time 10 --max-filesize 65536 \
  --output "$edge_retired_body" --dump-header "$edge_retired_headers" \
  --write-out '%{http_code}' "https://$EDGE_RETIRED_HOST/") || edge_fail
[ "$edge_retired_status" = "404" ] || edge_fail
[ "$(stat -c %s -- "$edge_retired_headers")" -le 65536 ] || edge_fail
if awk 'tolower($0) ~ /^(set-cookie|x-powered-by):/ { found=1 } END { exit(found ? 0 : 1) }' "$edge_retired_headers"; then
  edge_fail
fi
if grep -Eiq 'vasi|private engine|v.sign' "$edge_retired_body"; then
  edge_fail
fi

edge_evidence_result=$(docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 128m --cpus 1 --user 0:0 \
  -v "$EDGE_SOURCE_ROOT:/opt/vasi:ro" \
  -v "$EDGE_CONFIGURATION_FILE:/run/vasi-edge/monitor.json:ro" \
  -v "$EDGE_SCAN_ROOT:/evidence:ro" \
  -w /opt/vasi \
  "$EDGE_AUDITOR_IMAGE" node scripts/edge-monitor-contract.mjs verify-evidence \
  /run/vasi-edge/monitor.json /evidence "$edge_runtime_image_id") || edge_fail
edge_evidence_age=$(printf '%s' "$edge_evidence_result" | jq -er '.ageSeconds') || edge_fail
edge_evidence_artifacts=$(printf '%s' "$edge_evidence_result" | jq -er '.artifacts') || edge_fail
edge_assert_live_container
[ "$EDGE_LIVE_IMAGE_ID" = "$edge_runtime_image_id" ] || edge_fail
edge_assert_rollback_container
edge_assert_listener_bindings

printf '{"evidenceAgeSeconds":%s,"evidenceArtifacts":%s,"listenersChecked":%s,"schema":"vasi-edge-runtime-readiness/v1","status":"pass"}\n' \
  "$edge_evidence_age" "$edge_evidence_artifacts" "$EDGE_LISTENERS_CHECKED"
