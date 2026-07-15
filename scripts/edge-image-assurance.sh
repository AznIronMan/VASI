#!/bin/sh
set -eu
umask 077

. "$(dirname "$0")/edge-monitor-common.sh"

[ "$#" -eq 1 ] || edge_fail
edge_require_runtime
edge_load_policy

# Tool acquisition is allowed only in the daily image cycle. The frequent
# runtime probe is deliberately incapable of pulling or updating anything.
docker pull "$EDGE_AUDITOR_IMAGE" >/dev/null || edge_fail
docker pull "$EDGE_SCANNER_IMAGE" >/dev/null || edge_fail
edge_load_configuration "$1"
edge_take_lock
edge_protect_directory "$EDGE_SCAN_ROOT" /var/lib/vasi-edge
edge_protect_directory "$EDGE_SCANNER_CACHE" /var/cache/vasi-edge
edge_assert_live_container
edge_assert_rollback_container
edge_scanned_image_id=$EDGE_LIVE_IMAGE_ID

edge_scan_name="scan-$(date -u +%Y%m%dT%H%M%SZ)"
edge_final_directory="$EDGE_SCAN_ROOT/$edge_scan_name"
edge_temporary_directory="$EDGE_SCAN_ROOT/.tmp-$edge_scan_name-$$"
[ ! -e "$edge_final_directory" ] || edge_fail
[ ! -e "$edge_temporary_directory" ] || edge_fail
install -d -o root -g root -m 0700 "$edge_temporary_directory"
edge_image_archive="$edge_temporary_directory/image.tar"

edge_cleanup() {
  rm -f -- "$edge_image_archive"
  rm -f -- "${edge_latest_temporary:-}"
  if [ -n "${edge_temporary_directory:-}" ] && [ -d "$edge_temporary_directory" ]; then
    rm -rf -- "$edge_temporary_directory"
  fi
}
trap edge_cleanup EXIT HUP INT TERM

# Update the scanner database through a socket-free, capability-free tool
# container. The actual evidence scans below run with networking disabled.
docker run --rm --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 256 \
  --memory 1g --cpus 2 --user 0:0 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
  -v "$EDGE_SCANNER_CACHE:/trivy-cache:rw" \
  "$EDGE_SCANNER_IMAGE" image --cache-dir /trivy-cache \
  --quiet --download-db-only >/dev/null || edge_fail

docker image save "$edge_scanned_image_id" > "$edge_image_archive" || edge_fail
chmod 0600 "$edge_image_archive"

printf '%s\n' "$edge_scanned_image_id" > "$edge_temporary_directory/image-id.txt"
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 64 \
  --memory 128m --cpus 1 --user 65532:65532 \
  --entrypoint /sbin/apk "$edge_scanned_image_id" info -vv \
  | LC_ALL=C sort > "$edge_temporary_directory/packages.txt" || edge_fail
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 64 \
  --memory 128m --cpus 1 --user 0:0 \
  -v "$EDGE_SCANNER_CACHE:/trivy-cache:ro" \
  "$EDGE_SCANNER_IMAGE" version --cache-dir /trivy-cache --format json \
  > "$edge_temporary_directory/scanner-version.json" || edge_fail

(ulimit -f 32768; docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 256 \
  --memory 1g --cpus 2 --user 0:0 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
  -v "$edge_temporary_directory:/scan:ro" \
  -v "$EDGE_SCANNER_CACHE:/trivy-cache:rw" \
  "$EDGE_SCANNER_IMAGE" image --cache-dir /trivy-cache --quiet \
  --skip-db-update --offline-scan --scanners vuln --format json \
  --input /scan/image.tar) > "$edge_temporary_directory/vulnerabilities.json" || edge_fail

(ulimit -f 32768; docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 256 \
  --memory 1g --cpus 2 --user 0:0 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
  -v "$edge_temporary_directory:/scan:ro" \
  -v "$EDGE_SCANNER_CACHE:/trivy-cache:rw" \
  "$EDGE_SCANNER_IMAGE" image --cache-dir /trivy-cache --quiet \
  --skip-db-update --offline-scan --scanners vuln --format cyclonedx \
  --input /scan/image.tar) > "$edge_temporary_directory/sbom.cdx.json" || edge_fail

rm -f -- "$edge_image_archive"
edge_assert_live_container
[ "$EDGE_LIVE_IMAGE_ID" = "$edge_scanned_image_id" ] || edge_fail
edge_assert_rollback_container
edge_manifest_result=$(docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 128m --cpus 1 --user 0:0 \
  -v "$EDGE_SOURCE_ROOT:/opt/vasi:ro" \
  -v "$edge_temporary_directory:/evidence:rw" \
  -w /opt/vasi \
  "$EDGE_AUDITOR_IMAGE" node scripts/edge-monitor-contract.mjs \
  create-manifest /evidence "$edge_scan_name" "$edge_scanned_image_id") || edge_fail
edge_blocking_findings=$(printf '%s' "$edge_manifest_result" | jq -er '.blockingFindings') || edge_fail
edge_manifest_status=$(printf '%s' "$edge_manifest_result" | jq -er '.status') || edge_fail
chmod 0600 "$edge_temporary_directory"/*
mv -- "$edge_temporary_directory" "$edge_final_directory" || edge_fail
edge_temporary_directory=""

edge_latest_temporary="$EDGE_SCAN_ROOT/.latest-$$.json"
cp -- "$edge_final_directory/manifest.json" "$edge_latest_temporary" || edge_fail
chmod 0600 "$edge_latest_temporary"
mv -f -- "$edge_latest_temporary" "$EDGE_SCAN_ROOT/latest.json" || edge_fail
edge_latest_temporary=""
edge_assert_live_container
[ "$EDGE_LIVE_IMAGE_ID" = "$edge_scanned_image_id" ] || edge_fail
edge_assert_rollback_container

edge_retained=0
find "$EDGE_SCAN_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'scan-*' -printf '%f\n' \
  | LC_ALL=C sort -r \
  | while IFS= read -r edge_retained_name; do
      case "$edge_retained_name" in
        scan-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;;
        *) edge_fail ;;
      esac
      edge_retained=$((edge_retained + 1))
      if [ "$edge_retained" -gt "$EDGE_RETAINED_SCANS" ]; then
        rm -rf -- "$EDGE_SCAN_ROOT/$edge_retained_name"
      fi
    done

edge_retained_count=$(find "$EDGE_SCAN_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'scan-*' | wc -l | tr -d ' ')
printf '{"blockingFindings":%s,"retainedScans":%s,"schema":"vasi-edge-image-assurance-result/v1","status":"%s"}\n' \
  "$edge_blocking_findings" "$edge_retained_count" "$edge_manifest_status"
[ "$edge_manifest_status" = "pass" ] || exit 1
