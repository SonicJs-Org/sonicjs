/**
 * First-boot seed script for self-hosted SonicJS (Docker / Node / Bun).
 *
 * Creates an initial admin user when the database has no users yet.
 * Safe to run multiple times — exits silently if an admin already exists.
 * Safe to run BEFORE the server starts — applies migrations automatically.
 *
 * Usage:
 *   node --experimental-strip-types src/seed-self-host.ts
 *   # or via npm script (from my-sonicjs-app/):
 *   npm run reset
 *
 * Configure via environment variables:
 *   SONICJS_DB_PATH        Path to SQLite file (default: ./data/sonicjs.db)
 *   SONICJS_ADMIN_EMAIL    Admin email         (default: admin@sonicjs.com)
 *   SONICJS_ADMIN_PASSWORD Admin password      (default: sonicjs!)
 */

import { hashPassword } from '@better-auth/utils/password'
import { resolve, dirname } from 'node:path'
import { mkdirSync } from 'node:fs'
import { createSqliteDriver } from '@sonicjs-cms/core/adapters'
import { bootstrapDocumentTypes, RbacService } from '@sonicjs-cms/core'

const DB_PATH = resolve(process.env.SONICJS_DB_PATH ?? './data/sonicjs.db')
const ADMIN_EMAIL = process.env.SONICJS_ADMIN_EMAIL ?? 'admin@sonicjs.com'
const ADMIN_PASSWORD = process.env.SONICJS_ADMIN_PASSWORD ?? 'sonicjs!'

async function seed() {
  // Ensure data directory exists before opening DB.
  mkdirSync(dirname(DB_PATH), { recursive: true })

  // createSqliteDriver: opens DB, enables WAL, auto-migrates schema if absent.
  // Safe to run before the server — no concurrent connection needed.
  const driver = await createSqliteDriver({ dbPath: DB_PATH, autoMigrate: true })

  try {
    // Idempotency check — skip if any user already exists.
    const existing = await driver.prepare('SELECT COUNT(*) as n FROM auth_user').first<{ n: number }>()
    if (existing && existing.n > 0) {
      console.log('[seed] Admin already exists — skipping.')
      return
    }

    const now = Date.now()
    const userId = crypto.randomUUID()
    const accountId = crypto.randomUUID()

    const passwordHash = await hashPassword(ADMIN_PASSWORD)

    await driver.prepare(`
      INSERT INTO auth_user (
        id, email, name, first_name, last_name,
        role, is_super_admin, is_active,
        email_verified, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(userId, ADMIN_EMAIL, 'Admin', 'Admin', 'User', 'admin', 1, 1, 0, now, now).run()

    await driver.prepare(`
      INSERT INTO auth_account (
        id, user_id, account_id, provider_id, password, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(accountId, userId, userId, 'credential', passwordHash, now, now).run()

    // Bootstrap RBAC so the admin user can access /admin (requireRbac('portal', 'access')).
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await bootstrapDocumentTypes(driver as any)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rbac = new RbacService(driver as any)
    await rbac.ensureSystemRbacSeed()
    await rbac.addUserRoleByName(userId, 'admin')

    console.log('[seed] Admin user created:')
    console.log(`  Email:    ${ADMIN_EMAIL}`)
    console.log(`  Password: ${ADMIN_PASSWORD}`)
    if (ADMIN_PASSWORD === 'sonicjs!') {
      console.log('  ⚠ Change this password after first login!')
    }
  } finally {
    driver.close()
  }
}

seed().catch((err) => {
  console.error('[seed] Failed:', err)
  process.exit(1)
})
