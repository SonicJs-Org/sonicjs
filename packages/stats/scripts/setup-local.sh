#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Generate .dev.vars with BETTER_AUTH_SECRET if missing
if [ ! -f .dev.vars ]; then
  SECRET=$(openssl rand -hex 32 2>/dev/null || node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  echo "BETTER_AUTH_SECRET=\"${SECRET}\"" > .dev.vars
  echo "✓ Created .dev.vars"
elif ! grep -q '^BETTER_AUTH_SECRET=' .dev.vars; then
  SECRET=$(openssl rand -hex 32 2>/dev/null || node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  echo "BETTER_AUTH_SECRET=\"${SECRET}\"" >> .dev.vars
  echo "✓ Appended BETTER_AUTH_SECRET to .dev.vars"
fi

echo "Resetting local D1..."
rm -rf .wrangler/state/v3/d1

echo "Applying migrations..."
echo "y" | npx wrangler d1 migrations apply DB --local

echo "Seeding admin user..."
node scripts/seed-local.mjs

echo ""
echo "=========================================="
echo "Stats DB ready!"
echo "Admin: admin@sonicjs.com / sonicjs!"
echo "Run: npx wrangler dev"
echo "=========================================="
