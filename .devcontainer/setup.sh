#!/usr/bin/env bash
set -euo pipefail

# Devcontainer postCreate bootstrap.
#
# Bind-mounted workspaces inherit the host's file ownership. If the checkout
# was created by a root process, npm (running here as the `node` user) fails
# with `EPERM: operation not permitted, chmod` when it links workspace `bin`
# files (e.g. packages/core/bin/db-reset.js). This script normalises ownership
# so `npm install` works in the container without touching anything that
# Conductor or other CI flows rely on.

# Allow git to read the mount even if `.git` is owned by root.
git config --global --add safe.directory '*' || true

# Locate the repo root regardless of where the workspace is mounted.
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")"

# Make the whole workspace writable/ownable by the container user.
if ! sudo chown -R node:node "$REPO_ROOT"; then
  echo "WARNING: could not chown '$REPO_ROOT' to node:node —" \
    "npm install may fail with EPERM on bin files" >&2
fi

# Install dependencies so the workspace is immediately runnable.
#
# `node_modules` lives on Linux-native Docker volumes (see `mounts` in
# devcontainer.json) so npm never reifies against the host bind mount. On
# Docker Desktop + WSL2 (and some other bind mounts), `npm install` fails
# transiently with `EACCES: permission denied, rename node_modules/caniuse-lite`
# during npm's reify phase — npm renames directories while rebuilding the tree,
# and the 9p/drvfs mount intermittently rejects the rename, especially when a
# second install (e.g. one triggered by the IDE) is reifying the same tree
# concurrently. Ownership is fine; the failure is non-deterministic.
#
# Run unconditionally: install is idempotent and fast when the tree is already
# up to date, and re-running repairs any partially-installed state that the
# bind-mount failures left behind.
install_with_retry() {
  local attempts=4
  local attempt=1
  while true; do
    if npm --prefix "$REPO_ROOT" install; then
      return 0
    fi
    if (( attempt >= attempts )); then
      echo "npm install failed after $attempts attempts" >&2
      return 1
    fi
    echo "npm install failed (attempt $attempt/$attempts) — retrying..." >&2
    sleep 3
    attempt=$((attempt + 1))
  done
}

install_with_retry
