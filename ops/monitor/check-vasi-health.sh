#!/usr/bin/env bash

set -euo pipefail

for command in curl jq openssl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command is unavailable: $command" >&2
    exit 2
  fi
done

: "${VASI_PUBLIC_ORIGIN:?Set the canonical public HTTPS origin}"
: "${VASI_FALLBACK_ORIGIN:?Set the maintenance-only fallback HTTPS origin}"
: "${VASI_INTERNAL_ORIGIN:?Set the private HTTPS origin}"
: "${VASI_INTERNAL_CA_FILE:?Set the private-origin CA file}"

expected_deployed="${VASI_EXPECT_APPLICATION_DEPLOYED:-true}"
minimum_tls_days="${VASI_MINIMUM_TLS_DAYS:-30}"
connect_timeout="${VASI_CONNECT_TIMEOUT_SECONDS:-5}"
request_timeout="${VASI_REQUEST_TIMEOUT_SECONDS:-15}"

if [[ "$expected_deployed" != "true" && "$expected_deployed" != "false" ]]; then
  echo "VASI_EXPECT_APPLICATION_DEPLOYED must be true or false." >&2
  exit 2
fi

if ! [[ "$minimum_tls_days" =~ ^[0-9]+$ ]] || ((minimum_tls_days < 1)); then
  echo "VASI_MINIMUM_TLS_DAYS must be a positive integer." >&2
  exit 2
fi

if [[ ! -r "$VASI_INTERNAL_CA_FILE" ]]; then
  echo "The private-origin CA file is not readable." >&2
  exit 2
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/vasi-health.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

require_https_origin() {
  local name="$1"
  local value="$2"

  if [[ ! "$value" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]]; then
    echo "$name must be an HTTPS origin without credentials, path, query, or fragment." >&2
    exit 2
  fi

  local authority="${value#https://}"
  authority="${authority%/}"
  if [[ "$authority" == *:* ]]; then
    local port="${authority##*:}"
    if ((10#$port < 1 || 10#$port > 65535)); then
      echo "$name contains an invalid TCP port." >&2
      exit 2
    fi
  fi
}

require_https_origin VASI_PUBLIC_ORIGIN "$VASI_PUBLIC_ORIGIN"
require_https_origin VASI_FALLBACK_ORIGIN "$VASI_FALLBACK_ORIGIN"
require_https_origin VASI_INTERNAL_ORIGIN "$VASI_INTERNAL_ORIGIN"

VASI_PUBLIC_ORIGIN="${VASI_PUBLIC_ORIGIN%/}"
VASI_FALLBACK_ORIGIN="${VASI_FALLBACK_ORIGIN%/}"
VASI_INTERNAL_ORIGIN="${VASI_INTERNAL_ORIGIN%/}"

fetch_json() {
  local label="$1"
  local url="$2"
  local ca_file="${3:-}"
  local output="$tmp_dir/$label.json"
  local -a curl_args=(
    --silent
    --show-error
    --connect-timeout "$connect_timeout"
    --max-time "$request_timeout"
    --output "$output"
    --write-out '%{http_code}'
  )

  if [[ -n "$ca_file" ]]; then
    curl_args+=(--cacert "$ca_file")
  fi

  local status
  status="$(curl "${curl_args[@]}" "$url")"
  if [[ "$status" != "200" ]]; then
    echo "$label returned HTTP $status." >&2
    exit 1
  fi
  if ! jq -e 'type == "object" and (.status | type == "string")' "$output" >/dev/null; then
    echo "$label returned an invalid health document." >&2
    exit 1
  fi

  printf '%s\n' "$output"
}

public_health="$(fetch_json public "$VASI_PUBLIC_ORIGIN/healthz")"
fallback_health="$(fetch_json fallback "$VASI_FALLBACK_ORIGIN/healthz")"
internal_health="$(fetch_json internal "$VASI_INTERNAL_ORIGIN/healthz" "$VASI_INTERNAL_CA_FILE")"

if [[ "$expected_deployed" == "true" ]]; then
  jq -e '.application_deployed != false' "$public_health" >/dev/null || {
    echo "The canonical public endpoint still reports maintenance mode." >&2
    exit 1
  }
  jq -e '
    .status == "ok" and
    .checks.database.status == "ok" and
    .checks.certificate.status == "ok"
  ' "$internal_health" >/dev/null || {
    echo "The private application health check is not fully healthy." >&2
    exit 1
  }
else
  jq -e '.application_deployed == false' "$public_health" >/dev/null || {
    echo "The canonical public endpoint does not report the expected maintenance state." >&2
    exit 1
  }
  jq -e '.application_deployed == false' "$internal_health" >/dev/null || {
    echo "The private endpoint does not report the expected maintenance state." >&2
    exit 1
  }
fi

jq -e '.application_deployed == false' "$fallback_health" >/dev/null || {
  echo "The fallback endpoint must remain maintenance-only." >&2
  exit 1
}

echo "health public=ok internal=ok fallback=maintenance expected_deployed=$expected_deployed"

split_origin() {
  local origin="$1"
  local authority="${origin#https://}"

  authority="${authority%/}"
  if [[ "$authority" == *:* ]]; then
    tls_host="${authority%%:*}"
    tls_port="${authority##*:}"
  else
    tls_host="$authority"
    tls_port="443"
  fi
}

check_tls_expiry() {
  local label="$1"
  local ca_file="${2:-}"
  local certificate="$tmp_dir/$label.pem"
  local -a client_args=(
    -connect "$tls_host:$tls_port"
    -servername "$tls_host"
    -verify_hostname "$tls_host"
    -verify_return_error
  )

  if [[ -n "$ca_file" ]]; then
    client_args+=(-CAfile "$ca_file")
  fi

  if ! openssl s_client "${client_args[@]}" </dev/null 2>/dev/null |
    openssl x509 -outform PEM >"$certificate"; then
    echo "$label TLS chain or hostname verification failed." >&2
    exit 1
  fi

  if ! openssl x509 -in "$certificate" -noout -checkend "$((minimum_tls_days * 86400))" >/dev/null; then
    echo "$label TLS certificate expires within $minimum_tls_days days." >&2
    exit 1
  fi

  local not_after
  not_after="$(openssl x509 -in "$certificate" -noout -enddate | sed 's/^notAfter=//')"
  echo "tls $label=ok not_after=$not_after minimum_days=$minimum_tls_days"
}

split_origin "$VASI_PUBLIC_ORIGIN"
check_tls_expiry public
split_origin "$VASI_FALLBACK_ORIGIN"
check_tls_expiry fallback
split_origin "$VASI_INTERNAL_ORIGIN"
check_tls_expiry internal "$VASI_INTERNAL_CA_FILE"

echo "vasi_health_check=pass"
