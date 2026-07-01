/**
 * First-boot seed script for self-hosted SonicJS (Docker / Node / Bun).
 *
 * Creates an initial admin user when the database has no users yet.
 * Safe to run multiple times — exits silently if an admin already exists.
 *
 * Usage:
 *   node --experimental-strip-types src/seed-self-host.ts
 *   # or via npm script:
 *   npm run reset
 *
 * Configure via environment variables:
 *   SONICJS_DB_PATH       Path to SQLite file (default: ./data/sonicjs.db)
 *   SONICJS_ADMIN_EMAIL   Admin email         (default: admin@sonicjs.com)
 *   SONICJS_ADMIN_PASSWORD Admin password     (default: sonicjs!)
 */

import Database from 'better-sqlite3'
import { hashPassword } from '@better-auth/utils/password'
import { mkdirSync, existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'

const DB_PATH = resolve(process.env.SONICJS_DB_PATH ?? './data/sonicjs.db')
const ADMIN_EMAIL = process.env.SONICJS_ADMIN_EMAIL ?? 'admin@sonicjs.com'
const ADMIN_PASSWORD = process.env.SONICJS_ADMIN_PASSWORD ?? 'sonicjs!'

async function seed() {
  if (!existsSync(DB_PATH)) {
    console.error(`[seed] Database not found at ${DB_PATH}`)
    console.error('[seed] Start the server first so it auto-migrates, then run this script.')
    process.exit(1)
  }

  const db = new Database(DB_PATH)

  try {
    // Idempotency check — skip if any user already exists.
    const existing = db.prepare('SELECT COUNT(*) as n FROM auth_user').get() as { n: number }
    if (existing.n > 0) {
      console.log('[seed] Admin already exists — skipping.')
      return
    }

    const now = Date.now()
    const userId = crypto.randomUUID()
    const accountId = crypto.randomUUID()

    const passwordHash = await hashPassword(ADMIN_PASSWORD)

    db.prepare(`
      INSERT INTO auth_user (
        id, email, name, first_name, last_name,
        role, is_super_admin, is_active,
        email_verified, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(userId, ADMIN_EMAIL, 'Admin', 'Admin', 'User', 'admin', 1, 1, 0, now, now)

    db.prepare(`
      INSERT INTO auth_account (
        id, user_id, account_id, provider_id, password, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(accountId, userId, userId, 'credential', passwordHash, now, now)

    console.log('[seed] Admin user created:')
    console.log(`  Email:    ${ADMIN_EMAIL}`)
    console.log(`  Password: ${ADMIN_PASSWORD}`)
    if (ADMIN_PASSWORD === 'sonicjs!') {
      console.log('  ⚠ Change this password after first login!')
    }
  } finally {
    db.close()
  }
}

seed().catch((err) => {
  console.error('[seed] Failed:', err)
  process.exit(1)
})
