#!/bin/sh
# SonicJS Docker entrypoint
# On first boot (no DB file): runs seed which auto-migrates + creates admin.
# On subsequent boots: skips seed (idempotent check inside seed script).
# Sequential execution guarantees no concurrent SQLite writer conflict.
set -e

DB_PATH="${SONICJS_DB_PATH:-/app/data/sonicjs.db}"

if [ ! -f "$DB_PATH" ]; then
  echo "[entrypoint] First boot — running migrations + seed..."
  (cd /app/my-sonicjs-app && node --experimental-strip-types src/seed-self-host.ts)
fi

echo "[entrypoint] Starting SonicJS server..."
exec node --experimental-strip-types /app/my-sonicjs-app/src/self-host.ts
