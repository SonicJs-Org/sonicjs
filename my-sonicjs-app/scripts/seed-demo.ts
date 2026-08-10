/**
 * Seed script for local demo dev (npm run dev:demo).
 * Uses wrangler-demo.toml so it targets the same local miniflare D1 that
 * `wrangler dev --config wrangler-demo.toml` uses.
 * Idempotent: upserts the admin user and always resets the password.
 */
import { RbacService, bootstrapDocumentTypes } from '@sonicjs-cms/core'
import { getPlatformProxy } from 'wrangler'

async function hashPassword(password: string): Promise<string> {
  const iterations = 100000
  const salt = new Uint8Array(16)
  crypto.getRandomValues(salt)
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits'])
  const hashBuffer = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, 256)
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
  const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('')
  return `pbkdf2:${iterations}:${saltHex}:${hashHex}`
}

async function upsertUser(db: any, opts: {
  id: string; email: string; name: string; firstName: string; lastName: string
  role: string; rbacRole: string; password: string
}) {
  const passwordHash = await hashPassword(opts.password)
  const nowMs = Date.now()
  const nowSec = Math.floor(nowMs / 1000)
  const existing = await db.prepare('SELECT id FROM auth_user WHERE email = ?').bind(opts.email).first()
  if (existing) {
    await db.prepare('UPDATE auth_user SET updated_at = ? WHERE id = ?').bind(nowMs, existing.id).run()
    const cred = await db.prepare(`SELECT id FROM auth_account WHERE user_id = ? AND provider_id = 'credential'`).bind(existing.id).first()
    if (cred) {
      await db.prepare(`UPDATE auth_account SET password = ?, updated_at = ? WHERE id = ?`).bind(passwordHash, nowSec, cred.id).run()
    } else {
      await db.prepare(`INSERT INTO auth_account (id, user_id, account_id, provider_id, password, created_at, updated_at) VALUES (?, ?, ?, 'credential', ?, ?, ?)`)
        .bind(`cred-${existing.id}`, existing.id, existing.id, passwordHash, nowSec, nowSec).run()
    }
    await bootstrapDocumentTypes(db)
    const rbac = new RbacService(db)
    await rbac.ensureSystemRbacSeed()
    await rbac.addUserRoleByName(String(existing.id), opts.rbacRole)
    console.log(`✓ Updated: ${opts.email}`)
  } else {
    await db.batch([
      db.prepare(`INSERT INTO auth_user (id, name, email, email_verified, first_name, last_name, role, is_active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?, ?, 1, ?, ?)`)
        .bind(opts.id, opts.name, opts.email, opts.firstName, opts.lastName, opts.role, nowMs, nowMs),
      db.prepare(`INSERT INTO auth_account (id, user_id, account_id, provider_id, password, created_at, updated_at) VALUES (?, ?, ?, 'credential', ?, ?, ?)`)
        .bind(`cred-${opts.id}`, opts.id, opts.id, passwordHash, nowSec, nowSec),
    ])
    await bootstrapDocumentTypes(db)
    const rbac = new RbacService(db)
    await rbac.ensureSystemRbacSeed()
    await rbac.addUserRoleByName(opts.id, opts.rbacRole)
    console.log(`✓ Created: ${opts.email}`)
  }
}

async function seed() {
  const { env, dispose } = await getPlatformProxy({ configPath: './wrangler-demo.toml' })
  const db = (env as any).DB
  if (!db) { console.error('❌ DB binding not found — check wrangler-demo.toml'); process.exit(1) }

  try {
    await upsertUser(db, { id: 'admin-user-id', email: 'admin@sonicjs.com', name: 'Admin User', firstName: 'Admin', lastName: 'User', role: 'admin', rbacRole: 'admin', password: 'sonicjs!' })
    await upsertUser(db, { id: 'editor-user-eddie', email: 'e@e.com', name: 'Eddie McEditor', firstName: 'Eddie', lastName: 'McEditor', role: 'editor', rbacRole: 'editor', password: '123123123' })
    console.log('\nDemo credentials:\n  admin@sonicjs.com / sonicjs!\n  e@e.com / 123123123')
  } catch (err) {
    console.error('❌ Seed error:', err)
    await dispose()
    process.exit(1)
  }
  await dispose()
}

seed().then(() => { console.log('✓ Done'); process.exit(0) }).catch(e => { console.error(e); process.exit(1) })
