#!/bin/sh

set -eu

p12_path="${NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH:-/run/secrets/vasi-signing.p12}"
passphrase_path="${NEXT_PRIVATE_SIGNING_PASSPHRASE_FILE:-/run/secrets/vasi-signing-passphrase}"
work_dir="$(mktemp -d)"

cleanup() {
    rm -rf "$work_dir"
}

trap cleanup EXIT HUP INT TERM
umask 077

if [ ! -r "$p12_path" ] || [ ! -s "$p12_path" ]; then
    printf "The signing PKCS#12 file is missing, unreadable, or empty.\n" >&2
    exit 1
fi

if [ ! -r "$passphrase_path" ] || [ ! -s "$passphrase_path" ]; then
    printf "The signing passphrase file is missing, unreadable, or empty.\n" >&2
    exit 1
fi

openssl pkcs12 -in "$p12_path" -passin "file:$passphrase_path" \
    -clcerts -nokeys -out "$work_dir/certificate.pem" 2>/dev/null
openssl pkcs12 -in "$p12_path" -passin "file:$passphrase_path" \
    -nocerts -nodes 2>/dev/null \
    | openssl pkey -pubout -out "$work_dir/private-public.pem" 2>/dev/null
openssl x509 -in "$work_dir/certificate.pem" -pubkey -noout \
    > "$work_dir/certificate-public.pem"

certificate_key_hash="$(openssl dgst -sha256 "$work_dir/certificate-public.pem" | awk '{print $2}')"
private_key_hash="$(openssl dgst -sha256 "$work_dir/private-public.pem" | awk '{print $2}')"

if [ "$certificate_key_hash" != "$private_key_hash" ]; then
    printf "The PKCS#12 certificate does not match its private key.\n" >&2
    exit 1
fi

if ! openssl x509 -in "$work_dir/certificate.pem" -checkend 2592000 -noout >/dev/null; then
    printf "The signing certificate is expired or expires in fewer than 30 days.\n" >&2
    exit 1
fi

printf "Signing PKCS#12 integrity, key match, and 30-day validity checks passed.\n"
openssl x509 -in "$work_dir/certificate.pem" -noout -subject -issuer -startdate -enddate -fingerprint -sha256
