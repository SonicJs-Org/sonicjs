# SonicJS — self-hosted Docker image (Tier 1: SQLite + filesystem storage)
#
# Build:   docker build -t sonicjs .
# Run:     docker run -p 3000:3000 -v $(pwd)/data:/app/data \
#            -e JWT_SECRET=<secret> \
#            -e BETTER_AUTH_SECRET=<secret> \
#            sonicjs
#
# The data/ volume must be a persistent mount — SQLite DB and media files live there.

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM node:22-alpine AS builder

# Build tools required to compile better-sqlite3 native module.
RUN apk add --no-cache python3 make g++

# Upgrade to npm v11 — the lock file was generated with npm v11 on the host.
# npm v10 (bundled with Node 22) silently drops workspace transitive deps when reading npm v11 locks.
RUN npm install -g npm@11

WORKDIR /app

# Copy everything (source must be present before npm install runs workspace prepare scripts).
COPY package.json package-lock.json ./
COPY packages/core ./packages/core
COPY my-sonicjs-app ./my-sonicjs-app

# Install all deps + compile native modules + run prepare (builds @sonicjs-cms/core).
# Note: npm prune after workspace install drops workspace transitive deps (known npm issue),
# so we copy the full node_modules to the runtime stage instead of pruning.
RUN npm install --include=optional

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM node:22-alpine AS runtime

# System deps for better-sqlite3 native module.
RUN apk add --no-cache libc6-compat

WORKDIR /app

# Copy pruned node_modules with compiled better-sqlite3 binary from builder.
COPY --from=builder /app/node_modules ./node_modules

# Copy workspace manifests (needed for workspace symlink resolution at runtime).
COPY --from=builder /app/package.json ./
COPY --from=builder /app/packages/core/package.json ./packages/core/
COPY --from=builder /app/my-sonicjs-app/package.json ./my-sonicjs-app/

# Copy built core dist + migrations.
COPY --from=builder /app/packages/core/dist ./packages/core/dist
COPY --from=builder /app/packages/core/migrations ./packages/core/migrations

# Copy app source (self-host.ts + collections).
COPY --from=builder /app/my-sonicjs-app/src ./my-sonicjs-app/src
COPY --from=builder /app/my-sonicjs-app/tsconfig.json ./my-sonicjs-app/

# Persistent volume for SQLite DB + media uploads.
VOLUME ["/app/data"]

# Hono/Node server port.
EXPOSE 3000

ENV NODE_ENV=production
ENV ENVIRONMENT=production
ENV SONICJS_DB_PATH=/app/data/sonicjs.db
ENV SONICJS_STORAGE_PATH=/app/data/media
ENV SONICJS_KV_PATH=/app/data/kv.json
ENV PORT=3000

# Copy entrypoint script.
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

# Run as non-root for security.
RUN chown -R node:node /app && chmod +x /app/docker-entrypoint.sh
USER node

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Entrypoint: seeds DB on first boot then starts server (sequential, no concurrent SQLite access).
ENTRYPOINT ["/app/docker-entrypoint.sh"]
