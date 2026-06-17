#!/usr/bin/env node
/**
 * Local-only seed: inserts admin user directly into the miniflare SQLite file.
 * No Cloudflare auth or getPlatformProxy required.
 *
 * Usage: node scripts/seed-local.mjs [path-to-sqlite]
 */

import { createRequire } from 'module'
import { createHash, randomBytes, pbkdf2Sync } from 'node:crypto'
import { readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const require = createRequire(import.meta.url)
const Database = require('better-sqlite3')

// ── Locate SQLite file ──────────────────────────────────────────────────────

const scriptDir = new URL('.', import.meta.url).pathname
const appDir = join(scriptDir, '..')
const d1Dir = join(appDir, '.wrangler/state/v3/d1/miniflare-D1DatabaseObject')

let dbPath = process.argv[2]

if (!dbPath) {
  if (!existsSync(d1Dir)) {
    console.error('❌ No .wrangler/state/v3/d1 directory found.')
    console.error('   Run migrations first: echo "y" | npx wrangler d1 migrations apply <db-name> --local')
    process.exit(1)
  }
  const files = readdirSync(d1Dir).filter(f => f.endsWith('.sqlite'))
  if (files.length === 0) {
    console.error('❌ No SQLite file found in', d1Dir)
    process.exit(1)
  }
  dbPath = join(d1Dir, files[0])
}

console.log('📂 Using SQLite:', dbPath)

const db = new Database(dbPath)

// ── Password hashing (PBKDF2, matches seed-admin.ts) ───────────────────────

function hashPassword(password) {
  const iterations = 100000
  const salt = randomBytes(16)
  const hash = pbkdf2Sync(password, salt, iterations, 32, 'sha256')
  return `pbkdf2:${iterations}:${salt.toString('hex')}:${hash.toString('hex')}`
}

// ── Admin user ──────────────────────────────────────────────────────────────

const EMAIL = 'admin@sonicjs.com'
const PASSWORD = 'sonicjs!'

const existing = db.prepare('SELECT id FROM auth_user WHERE email = ?').get(EMAIL)

if (existing) {
  console.log('✓ Admin user already exists')
} else {
  const now = Math.floor(Date.now() / 1000)
  const userId = `admin-${Date.now()}-${randomBytes(4).toString('hex')}`
  const passwordHash = hashPassword(PASSWORD)

  db.prepare(`
    INSERT INTO auth_user (id, email, first_name, last_name, role, is_active, created_at, updated_at, name, email_verified)
    VALUES (?, ?, 'Admin', 'User', 'admin', 1, ?, ?, 'Admin User', 1)
  `).run(userId, EMAIL, now, now)

  db.prepare(`
    INSERT INTO auth_account (id, user_id, account_id, provider_id, password, created_at, updated_at)
    VALUES (?, ?, ?, 'credential', ?, ?, ?)
  `).run(randomBytes(16).toString('hex'), userId, userId, passwordHash, now, now)

  console.log('✓ Admin user created')
  console.log('  Email:', EMAIL)
  console.log('  Password:', PASSWORD)
  console.log('  Role: admin')
}

db.close()
console.log('✓ Seed complete')
