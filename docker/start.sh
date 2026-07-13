#!/bin/sh

set -eu

run_migrations() {
    printf "🗄️  Running database migrations...\n"

    if [ -n "${NEXT_PRIVATE_DATABASE_URL_FILE:-}" ]; then
        if [ -n "${NEXT_PRIVATE_DATABASE_URL:-}" ]; then
            printf "NEXT_PRIVATE_DATABASE_URL and NEXT_PRIVATE_DATABASE_URL_FILE cannot both be set.\n" >&2
            exit 1
        fi

        database_url="$(tr -d '\r\n' < "$NEXT_PRIVATE_DATABASE_URL_FILE")"

        if [ -z "$database_url" ]; then
            printf "NEXT_PRIVATE_DATABASE_URL_FILE points to an empty secret.\n" >&2
            exit 1
        fi

        if [ -n "${NEXT_PRIVATE_DIRECT_DATABASE_URL_FILE:-}" ]; then
            if [ -n "${NEXT_PRIVATE_DIRECT_DATABASE_URL:-}" ]; then
                printf "NEXT_PRIVATE_DIRECT_DATABASE_URL and NEXT_PRIVATE_DIRECT_DATABASE_URL_FILE cannot both be set.\n" >&2
                exit 1
            fi

            direct_database_url="$(tr -d '\r\n' < "$NEXT_PRIVATE_DIRECT_DATABASE_URL_FILE")"
        elif [ -n "${NEXT_PRIVATE_DIRECT_DATABASE_URL:-}" ]; then
            direct_database_url="$NEXT_PRIVATE_DIRECT_DATABASE_URL"
        else
            direct_database_url="$database_url"
        fi

        if [ -z "$direct_database_url" ]; then
            printf "The direct database URL is empty.\n" >&2
            exit 1
        fi

        NEXT_PRIVATE_DATABASE_URL="$database_url" \
            NEXT_PRIVATE_DIRECT_DATABASE_URL="$direct_database_url" \
            npx prisma migrate deploy --schema ../../packages/prisma/schema.prisma

        unset database_url direct_database_url
    else
        npx prisma migrate deploy --schema ../../packages/prisma/schema.prisma
    fi
}

printf "🚀 Starting VASI...\n\n"

# 🔐 Check certificate configuration
printf "🔐 Checking certificate configuration...\n"

CERT_PATH="${NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH:-/opt/documenso/cert.p12}"

if [ -f "$CERT_PATH" ] && [ -r "$CERT_PATH" ]; then
    printf "✅ Certificate file found and readable - document signing is ready!\n"
else
    printf "⚠️ Certificate not found or not readable\n"
    printf "💡 VASI will start, but document signing will be unavailable\n"
fi

printf "\n📚 Runtime checks:\n"
printf "🏥 Health check: http://localhost:3000/api/health\n"
printf "📊 Certificate status: http://localhost:3000/api/certificate-status\n"
printf "📦 Corresponding source: https://github.com/AznIronMan/VASI\n\n"

if [ "${VASI_MIGRATE_ONLY:-false}" = "true" ]; then
    run_migrations
    printf "✅ Database migrations completed.\n"
    exit 0
fi

if [ "${VASI_BOOTSTRAP_ADMIN:-false}" = "true" ]; then
    run_migrations
    node bootstrap-admin.mjs
    printf "✅ Initial VASI administrator bootstrap completed.\n"
    exit 0
fi

if [ "${VASI_RUN_MIGRATIONS:-true}" = "true" ]; then
    run_migrations
fi

printf "🌟 Starting VASI server...\n"
exec env HOSTNAME=0.0.0.0 node build/server/main.js
