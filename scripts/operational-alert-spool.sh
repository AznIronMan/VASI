#!/bin/sh
set -eu

umask 077

MAX_PENDING=256
MAX_ACKNOWLEDGED=1024

fail() {
  printf '%s\n' "VASI operational alert spool failed closed." >&2
  exit 1
}

usage() {
  printf '%s\n' \
    "Usage: operational-alert-spool.sh record ROLE SOURCE_UNIT" \
    "       operational-alert-spool.sh status ROLE" \
    "       operational-alert-spool.sh next ROLE" \
    "       operational-alert-spool.sh acknowledge ROLE RECORD_ID OPAQUE_REFERENCE" >&2
  exit 64
}

stat_value() {
  linux_format=$1
  bsd_format=$2
  target=$3
  stat -c "$linux_format" -- "$target" 2>/dev/null || stat -f "$bsd_format" -- "$target" 2>/dev/null
}

file_uid() {
  stat_value %u %u "$1"
}

file_mode() {
  stat_value %a %Lp "$1"
}

file_mtime() {
  stat_value %Y %m "$1"
}

physical_directory() {
  (CDPATH= cd -- "$1" 2>/dev/null && pwd -P)
}

is_safe_token() {
  value=$1
  [ -n "$value" ] && [ "${#value}" -le 64 ] || return 1
  case "$value" in
    *[!A-Za-z0-9_.:-]*) return 1 ;;
  esac
}

safe_token_or_unknown() {
  if is_safe_token "$1"; then
    printf '%s' "$1"
  else
    printf '%s' unknown
  fi
}

validate_role() {
  case "$1" in
    gateway|engine|edge) ;;
    *) fail ;;
  esac
}

is_allowed_unit() {
  role=$1
  unit=$2
  case "$role:$unit" in
    gateway:vasi-gateway-backup-check.service|\
    gateway:vasi-gateway-backup-create.service|\
    gateway:vasi-gateway-capacity-readiness.service|\
    gateway:vasi-gateway-deployment-readiness.service|\
    gateway:vasi-gateway-operational-readiness.service|\
    engine:vasi-engine-backup-check.service|\
    engine:vasi-engine-backup-create.service|\
    engine:vasi-engine-capacity-readiness.service|\
    engine:vasi-engine-database-egress-policy.service|\
    engine:vasi-engine-deployment-readiness.service|\
    engine:vasi-engine-egress-boundary.service|\
    engine:vasi-engine-operational-readiness.service|\
    edge:vasi-edge-image-assurance.service|\
    edge:vasi-edge-runtime-readiness.service) return 0 ;;
    *) return 1 ;;
  esac
}

state_root_for_role() {
  case "$1" in
    gateway) printf '%s' /var/lib/vasi/operations-alerts ;;
    engine) printf '%s' /var/lib/vasi-engine/operations-alerts ;;
    edge) printf '%s' /var/lib/vasi-edge/operations-alerts ;;
    *) fail ;;
  esac
}

ensure_directory() {
  directory=$1
  if [ ! -e "$directory" ]; then
    mkdir -m 700 -- "$directory" 2>/dev/null || [ -d "$directory" ] || fail
  fi
  [ -d "$directory" ] && [ ! -L "$directory" ] || fail
  [ "$(physical_directory "$directory")" = "$directory" ] || fail
  [ "$(file_uid "$directory")" = "$EXPECTED_UID" ] || fail
  [ "$(file_mode "$directory")" = 700 ] || fail
}

validate_regular_file() {
  filename=$1
  maximum_bytes=$2
  [ -f "$filename" ] && [ ! -L "$filename" ] || return 1
  [ "$(file_uid "$filename")" = "$EXPECTED_UID" ] || return 1
  [ "$(file_mode "$filename")" = 600 ] || return 1
  bytes=$(wc -c < "$filename" | tr -d ' ')
  [ "$bytes" -ge 2 ] && [ "$bytes" -le "$maximum_bytes" ] || return 1
}

random_hex() {
  value=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n') || fail
  printf '%s\n' "$value" | grep -Eq '^[a-f0-9]{32}$' || fail
  printf '%s' "$value"
}

timestamp() {
  date -u +%Y%m%dT%H%M%SZ
}

sync_state() {
  if [ -z "${VASI_OPERATIONAL_ALERT_TEST_ROOT:-}" ]; then
    sync
  fi
}

acquire_lock() {
  LOCK_FILE=$STATE_ROOT/.lock
  if [ ! -e "$LOCK_FILE" ]; then
    (umask 077; : > "$LOCK_FILE") || fail
  fi
  [ -f "$LOCK_FILE" ] && [ ! -L "$LOCK_FILE" ] || fail
  [ "$(file_uid "$LOCK_FILE")" = "$EXPECTED_UID" ] || fail
  [ "$(file_mode "$LOCK_FILE")" = 600 ] || fail
  [ "$(wc -c < "$LOCK_FILE" | tr -d ' ')" -le 64 ] || fail
  if command -v flock >/dev/null 2>&1; then
    exec 9>>"$LOCK_FILE"
    flock -w 5 9 || fail
    LOCK_KIND=flock
    return
  fi

  LOCK_DIRECTORY=$STATE_ROOT/.lock-directory
  attempts=0
  while ! mkdir -m 700 -- "$LOCK_DIRECTORY" 2>/dev/null; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 5 ] || fail
    sleep 1
  done
  LOCK_KIND=directory
  trap release_lock EXIT HUP INT TERM
}

release_lock() {
  if [ "${LOCK_KIND:-}" = directory ] && [ -n "${LOCK_DIRECTORY:-}" ]; then
    rmdir -- "$LOCK_DIRECTORY" 2>/dev/null || true
    LOCK_KIND=released
  fi
}

pending_files() {
  find "$PENDING_DIRECTORY" -mindepth 1 -maxdepth 1 -print | LC_ALL=C sort
}

acknowledged_files() {
  find "$ACKNOWLEDGED_DIRECTORY" -mindepth 1 -maxdepth 1 -print | LC_ALL=C sort
}

validate_record_contents() {
  filename=$1
  expected_record_id=$2
  validate_regular_file "$filename" 2048 || return 1
  [ "$(wc -l < "$filename" | tr -d ' ')" = 1 ] || return 1
  line=$(sed -n '1p' "$filename")
  printf '%s\n' "$line" | grep -Eq '^\{"exitCode":"[A-Za-z0-9_.:-]{1,64}","exitStatus":"[A-Za-z0-9_.:-]{1,64}","invocationId":"(unknown|[a-f0-9]{32})","occurredAt":"[0-9]{8}T[0-9]{6}Z","recordId":"[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}\.json","role":"(gateway|engine|edge)","schema":"vasi-operational-alert/v1","serviceResult":"[A-Za-z0-9_.:-]{1,64}","sourceUnit":"vasi-(gateway|engine|edge)-[a-z0-9-]+\.service"\}$' || return 1
  printf '%s\n' "$line" | grep -Fq "\"recordId\":\"$expected_record_id\"" || return 1
  printf '%s\n' "$line" | grep -Fq "\"role\":\"$ROLE\"" || return 1
  record_unit=$(printf '%s\n' "$line" | sed -n 's/^.*"sourceUnit":"\([^"]*\)"}$/\1/p')
  is_allowed_unit "$ROLE" "$record_unit" || return 1
}

validate_record() {
  filename=$1
  base=$(basename -- "$filename")
  printf '%s\n' "$base" | grep -Eq '^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}\.json$' || return 1
  validate_record_contents "$filename" "$base"
}

validate_overflow_contents() {
  filename=$1
  validate_regular_file "$filename" 1024 || return 1
  [ "$(wc -l < "$filename" | tr -d ' ')" = 1 ] || return 1
  line=$(sed -n '1p' "$filename")
  printf '%s\n' "$line" | grep -Eq '^\{"lastOccurredAt":"[0-9]{8}T[0-9]{6}Z","lastSourceUnit":"vasi-(gateway|engine|edge)-[a-z0-9-]+\.service","overflowCount":[0-9]{1,9},"recordId":"overflow","role":"(gateway|engine|edge)","schema":"vasi-operational-alert-overflow/v1"\}$' || return 1
  printf '%s\n' "$line" | grep -Fq "\"role\":\"$ROLE\"" || return 1
  overflow_unit=$(printf '%s\n' "$line" | sed -n 's/^.*"lastSourceUnit":"\([^"]*\)".*$/\1/p')
  is_allowed_unit "$ROLE" "$overflow_unit" || return 1
}

validate_overflow() {
  [ -e "$OVERFLOW_FILE" ] || return 2
  validate_overflow_contents "$OVERFLOW_FILE"
}

validate_acknowledged_entry() {
  filename=$1
  base=$(basename -- "$filename")
  printf '%s\n' "$base" | grep -Eq '^([0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}|overflow)--ack-[0-9]{8}T[0-9]{6}Z-[a-z0-9][a-z0-9._-]{0,63}\.json$' || return 1
  original=${base%%--ack-*}
  if [ "$original" = overflow ]; then
    validate_overflow_contents "$filename"
  else
    validate_record_contents "$filename" "$original.json"
  fi
}

overflow_count() {
  if validate_overflow; then
    sed -n 's/^.*"overflowCount":\([0-9][0-9]*\).*$/\1/p' "$OVERFLOW_FILE"
    return
  else
    result=$?
  fi
  [ "$result" -eq 2 ] || fail
  printf '%s' 0
}

write_overflow() {
  source_unit=$1
  occurred_at=$2
  count=$(overflow_count)
  if [ "$count" -lt 999999999 ]; then
    count=$((count + 1))
  fi
  temporary=$(mktemp "$STATE_ROOT/.overflow.XXXXXX") || fail
  trap 'rm -f -- "${temporary:-}"; release_lock' EXIT HUP INT TERM
  printf '{"lastOccurredAt":"%s","lastSourceUnit":"%s","overflowCount":%s,"recordId":"overflow","role":"%s","schema":"vasi-operational-alert-overflow/v1"}\n' \
    "$occurred_at" "$source_unit" "$count" "$ROLE" > "$temporary"
  chmod 600 "$temporary"
  validate_regular_file "$temporary" 1024 || fail
  sync_state
  mv -f -- "$temporary" "$OVERFLOW_FILE"
  temporary=
  sync_state
}

count_pending() {
  pending_count=0
  while IFS= read -r filename; do
    [ -n "$filename" ] || continue
    pending_count=$((pending_count + 1))
  done <<EOF
$(pending_files)
EOF
  printf '%s' "$pending_count"
}

record_failure() {
  [ "$#" -eq 1 ] || usage
  source_unit=$1
  is_allowed_unit "$ROLE" "$source_unit" || fail
  if [ -n "${MONITOR_UNIT:-}" ] && [ "$MONITOR_UNIT" != "$source_unit" ]; then
    fail
  fi

  acquire_lock
  pending_count=$(count_pending)
  [ "$pending_count" -le "$MAX_PENDING" ] || fail
  occurred_at=$(timestamp)
  if [ "$pending_count" -eq "$MAX_PENDING" ]; then
    write_overflow "$source_unit" "$occurred_at"
    printf '{"recordId":"overflow","role":"%s","schema":"vasi-operational-alert-record-result/v1","status":"recorded"}\n' "$ROLE"
    release_lock
    return
  fi

  random=$(random_hex)
  record_id="$occurred_at-$random.json"
  final=$PENDING_DIRECTORY/$record_id
  [ ! -e "$final" ] || fail
  temporary=$(mktemp "$PENDING_DIRECTORY/.record.XXXXXX") || fail
  trap 'rm -f -- "${temporary:-}"; release_lock' EXIT HUP INT TERM
  exit_code=$(safe_token_or_unknown "${MONITOR_EXIT_CODE:-}")
  exit_status=$(safe_token_or_unknown "${MONITOR_EXIT_STATUS:-}")
  invocation_id=${MONITOR_INVOCATION_ID:-}
  printf '%s\n' "$invocation_id" | grep -Eq '^[a-f0-9]{32}$' || invocation_id=unknown
  service_result=$(safe_token_or_unknown "${MONITOR_SERVICE_RESULT:-}")
  printf '{"exitCode":"%s","exitStatus":"%s","invocationId":"%s","occurredAt":"%s","recordId":"%s","role":"%s","schema":"vasi-operational-alert/v1","serviceResult":"%s","sourceUnit":"%s"}\n' \
    "$exit_code" "$exit_status" "$invocation_id" "$occurred_at" "$record_id" "$ROLE" "$service_result" "$source_unit" > "$temporary"
  chmod 600 "$temporary"
  validate_regular_file "$temporary" 2048 || fail
  sync_state
  mv -- "$temporary" "$final"
  temporary=
  validate_record "$final" || { rm -f -- "$final"; fail; }
  sync_state
  printf '{"recordId":"%s","role":"%s","schema":"vasi-operational-alert-record-result/v1","status":"recorded"}\n' \
    "$record_id" "$ROLE"
  release_lock
}

status_spool() {
  [ "$#" -eq 0 ] || usage
  acquire_lock
  pending_count=0
  invalid_count=0
  oldest_epoch=
  now=$(date +%s)
  while IFS= read -r filename; do
    [ -n "$filename" ] || continue
    if validate_record "$filename"; then
      pending_count=$((pending_count + 1))
      modified=$(file_mtime "$filename") || modified=
      case "$modified" in
        ''|*[!0-9]*) invalid_count=$((invalid_count + 1)) ;;
        *)
          if [ "$modified" -gt "$now" ]; then
            invalid_count=$((invalid_count + 1))
          elif [ -z "$oldest_epoch" ] || [ "$modified" -lt "$oldest_epoch" ]; then
            oldest_epoch=$modified
          fi
          ;;
      esac
    else
      invalid_count=$((invalid_count + 1))
    fi
  done <<EOF
$(pending_files)
EOF
  [ "$pending_count" -le "$MAX_PENDING" ] || invalid_count=$((invalid_count + 1))

  overflow=0
  if validate_overflow; then
    overflow=$(sed -n 's/^.*"overflowCount":\([0-9][0-9]*\).*$/\1/p' "$OVERFLOW_FILE")
  else
    result=$?
    [ "$result" -eq 2 ] || invalid_count=$((invalid_count + 1))
  fi
  oldest_age=0
  if [ -n "$oldest_epoch" ]; then
    oldest_age=$((now - oldest_epoch))
  fi

  state=ready
  exit_status=0
  if [ "$invalid_count" -gt 0 ]; then
    state=invalid
    exit_status=1
  elif [ "$pending_count" -gt 0 ] || [ "$overflow" -gt 0 ]; then
    state=pending
    exit_status=1
  fi
  printf '{"invalidRecords":%s,"oldestPendingAgeSeconds":%s,"overflowCount":%s,"pendingRecords":%s,"role":"%s","schema":"vasi-operational-alert-spool/v1","status":"%s"}\n' \
    "$invalid_count" "$oldest_age" "$overflow" "$pending_count" "$ROLE" "$state"
  release_lock
  return "$exit_status"
}

next_record() {
  [ "$#" -eq 0 ] || usage
  acquire_lock
  if validate_overflow; then
    sed -n '1p' "$OVERFLOW_FILE"
    release_lock
    return
  else
    result=$?
  fi
  [ "$result" -eq 2 ] || fail
  while IFS= read -r filename; do
    [ -n "$filename" ] || continue
    validate_record "$filename" || fail
    sed -n '1p' "$filename"
    release_lock
    return
  done <<EOF
$(pending_files)
EOF
  printf '%s\n' null
  release_lock
}

prune_acknowledged() {
  total=0
  while IFS= read -r filename; do
    [ -n "$filename" ] || continue
    validate_acknowledged_entry "$filename" || fail
    total=$((total + 1))
  done <<EOF
$(acknowledged_files)
EOF
  remove_count=$((total - MAX_ACKNOWLEDGED))
  if [ "$remove_count" -le 0 ]; then
    return 0
  fi
  count=0
  while IFS= read -r filename; do
    [ -n "$filename" ] || continue
    count=$((count + 1))
    if [ "$count" -le "$remove_count" ]; then
      validate_regular_file "$filename" 2048 || fail
      rm -f -- "$filename"
    fi
  done <<EOF
$(acknowledged_files)
EOF
}

validate_acknowledged_state() {
  while IFS= read -r filename; do
    [ -n "$filename" ] || continue
    validate_acknowledged_entry "$filename" || fail
  done <<EOF
$(acknowledged_files)
EOF
}

acknowledge_record() {
  [ "$#" -eq 2 ] || usage
  record_id=$1
  reference=$2
  [ -n "$reference" ] && [ "${#reference}" -le 64 ] || fail
  printf '%s\n' "$reference" | grep -Eq '^[a-z0-9][a-z0-9._-]*$' || fail
  acquire_lock
  validate_acknowledged_state
  acknowledged_at=$(timestamp)

  if [ "$record_id" = overflow ]; then
    validate_overflow || fail
    source=$OVERFLOW_FILE
    destination=$ACKNOWLEDGED_DIRECTORY/overflow--ack-$acknowledged_at-$reference.json
  else
    printf '%s\n' "$record_id" | grep -Eq '^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}\.json$' || fail
    source=$PENDING_DIRECTORY/$record_id
    validate_record "$source" || fail
    destination=$ACKNOWLEDGED_DIRECTORY/${record_id%.json}--ack-$acknowledged_at-$reference.json
  fi
  [ ! -e "$destination" ] || fail
  mv -- "$source" "$destination"
  sync_state
  prune_acknowledged
  printf '{"acknowledgedAt":"%s","recordId":"%s","role":"%s","schema":"vasi-operational-alert-acknowledgement/v1","status":"acknowledged"}\n' \
    "$acknowledged_at" "$record_id" "$ROLE"
  release_lock
}

[ "$#" -ge 2 ] || usage
COMMAND=$1
ROLE=$2
shift 2
validate_role "$ROLE"

if [ -n "${VASI_OPERATIONAL_ALERT_TEST_ROOT:-}" ]; then
  case "$VASI_OPERATIONAL_ALERT_TEST_ROOT" in
    /*) ;;
    *) fail ;;
  esac
  TEST_ROOT=$(physical_directory "$VASI_OPERATIONAL_ALERT_TEST_ROOT") || fail
  [ "$TEST_ROOT" = "$VASI_OPERATIONAL_ALERT_TEST_ROOT" ] || fail
  EXPECTED_UID=$(id -u)
  STATE_ROOT=$TEST_ROOT/$ROLE
else
  [ "$(id -u)" -eq 0 ] || fail
  EXPECTED_UID=0
  STATE_ROOT=$(state_root_for_role "$ROLE")
fi

ensure_directory "$STATE_ROOT"
PENDING_DIRECTORY=$STATE_ROOT/pending
ACKNOWLEDGED_DIRECTORY=$STATE_ROOT/acknowledged
OVERFLOW_FILE=$STATE_ROOT/overflow.json
ensure_directory "$PENDING_DIRECTORY"
ensure_directory "$ACKNOWLEDGED_DIRECTORY"

case "$COMMAND" in
  record) record_failure "$@" ;;
  status) status_spool "$@" ;;
  next) next_record "$@" ;;
  acknowledge) acknowledge_record "$@" ;;
  *) usage ;;
esac
