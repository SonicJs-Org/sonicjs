#!/bin/bash

# Setup a fresh D1 database for this worktree
# This script creates a new D1 database named after the current git branch
# and updates wrangler.toml to use it

set -e

# Get the current branch name
BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
if [ -z "$BRANCH_NAME" ] || [ "$BRANCH_NAME" = "HEAD" ]; then
  echo "Error: Could not determine branch name"
  exit 1
fi

# Create a safe database name from branch
SAFE_BRANCH=$(echo "$BRANCH_NAME" | sed 's/[^a-zA-Z0-9-]/-/g' | cut -c1-50)
DB_NAME="sonicjs-worktree-${SAFE_BRANCH}"

echo "Setting up fresh D1 database for worktree: $BRANCH_NAME"
echo "Database name: $DB_NAME"

# Change to my-sonicjs-app directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Ensure .dev.vars exists with required secrets. Wrangler loads it for local
# dev; without BETTER_AUTH_SECRET, auth init throws and login returns 500.
gen_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  fi
}

if [ ! -f .dev.vars ]; then
  echo ""
  echo "Generating .dev.vars with a fresh BETTER_AUTH_SECRET..."
  AUTH_SECRET=$(gen_secret)
  cat > .dev.vars <<EOF
# Local dev secrets — gitignored. Do not commit.
# Regenerate BETTER_AUTH_SECRET with: openssl rand -hex 32
BETTER_AUTH_SECRET="$AUTH_SECRET"
EOF
  echo ".dev.vars created."
elif ! grep -q '^BETTER_AUTH_SECRET=' .dev.vars; then
  echo "Appending BETTER_AUTH_SECRET to existing .dev.vars..."
  AUTH_SECRET=$(gen_secret)
  echo "BETTER_AUTH_SECRET=\"$AUTH_SECRET\"" >> .dev.vars
fi

# Check if database already exists
echo "Checking for existing database..."
EXISTING_DB=$(npx wrangler d1 list --json 2>/dev/null | jq -r ".[] | select(.name == \"$DB_NAME\") | .uuid" || echo "")

if [ -n "$EXISTING_DB" ]; then
  echo "Database $DB_NAME already exists with ID: $EXISTING_DB"
  DB_ID="$EXISTING_DB"

  # Ask if user wants to delete and recreate
  read -p "Delete existing database and create fresh one? (y/N): " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Deleting existing database..."
    npx wrangler d1 delete "$DB_NAME" --skip-confirmation
    EXISTING_DB=""
  fi
fi

if [ -z "$EXISTING_DB" ]; then
  # Create new database
  echo "Creating new D1 database: $DB_NAME"
  CREATE_OUTPUT=$(npx wrangler d1 create "$DB_NAME" 2>&1)
  echo "$CREATE_OUTPUT"

  # Extract database ID from creation output
  DB_ID=$(echo "$CREATE_OUTPUT" | grep -oE 'database_id\s*=\s*"[^"]+"' | grep -oE '"[^"]+"' | tr -d '"' || echo "")

  if [ -z "$DB_ID" ]; then
    # Try alternative extraction method
    DB_ID=$(npx wrangler d1 list --json | jq -r ".[] | select(.name == \"$DB_NAME\") | .uuid")
  fi
fi

if [ -z "$DB_ID" ]; then
  echo "Error: Failed to get database ID"
  exit 1
fi

echo "Database ID: $DB_ID"

# Update wrangler.toml with the new database ID
echo "Updating wrangler.toml..."

# Use sed to replace database_id and database_name
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS sed requires empty string after -i
  sed -i '' "s/database_id = \"[^\"]*\"/database_id = \"$DB_ID\"/" wrangler.toml
  sed -i '' "s/database_name = \"[^\"]*\"/database_name = \"$DB_NAME\"/" wrangler.toml
else
  # Linux sed
  sed -i "s/database_id = \"[^\"]*\"/database_id = \"$DB_ID\"/" wrangler.toml
  sed -i "s/database_name = \"[^\"]*\"/database_name = \"$DB_NAME\"/" wrangler.toml
fi

echo "Updated wrangler.toml:"
grep -A2 "d1_databases" wrangler.toml

# Reset local database by removing it
echo ""
echo "Resetting local database..."
rm -rf .wrangler/state/v3/d1
echo "Local database cleared."

# Run migrations on remote
echo ""
echo "Running migrations on remote database..."
echo "y" | npx wrangler d1 migrations apply "$DB_NAME" --remote

# Run migrations on local
echo ""
echo "Running migrations on local database..."
echo "y" | npx wrangler d1 migrations apply "$DB_NAME" --local

# Seed admin user
echo ""
echo "Seeding admin user..."
npx tsx scripts/seed-admin.ts

# Seed default welcome blog post
echo ""
echo "Seeding default blog content..."
npx tsx scripts/seed-documents.ts

echo ""
echo "=========================================="
echo "Database setup complete!"
echo "Database name: $DB_NAME"
echo "Database ID: $DB_ID"
echo "Both remote and local databases are ready."
echo "Admin user: admin@sonicjs.com / sonicjs!"
echo "=========================================="
echo ""
echo "You can now run: npm run dev"
