import { createDb, users, RbacService, bootstrapDocumentTypes } from '@sonicjs-cms/core'
import { eq } from 'drizzle-orm'
import { getPlatformProxy } from 'wrangler'

/**
 * Hash password using PBKDF2 via Web Crypto API (same as SonicJS AuthManager)
 */
async function hashPassword(password: string): Promise<string> {
  const iterations = 100000
  const salt = new Uint8Array(16)
  crypto.getRandomValues(salt)

  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  )

  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  )

  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
  const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('')

  return `pbkdf2:${iterations}:${saltHex}:${hashHex}`
}

/**
 * Seed script to create initial admin user
 *
 * Run this script after migrations:
 * npm run db:migrate:local
 * npm run seed
 *
 * Admin credentials:
 * Email: admin@sonicjs.com
 * Password: sonicjs!
 */

async function seed() {
  // Get D1 database from Cloudflare environment using wrangler's getPlatformProxy
  const { env, dispose } = await getPlatformProxy()

  if (!env?.DB) {
    console.error('❌ Error: DB binding not found')
    console.error('')
    console.error('Make sure you have:')
    console.error('1. Created your D1 database: wrangler d1 create <database-name>')
    console.error('2. Updated wrangler.toml with the database_id')
    console.error('3. Run migrations: npm run db:migrate:local')
    console.error('')
    process.exit(1)
  }

  const db = createDb(env.DB)

  try {
    // Check if admin user already exists
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, 'admin@sonicjs.com'))
      .get()

    if (existingUser) {
      console.log('✓ Admin user already exists')
      console.log(`  Email: admin@sonicjs.com`)
      console.log(`  Role: ${existingUser.role}`)
      await dispose()
      return
    }

    // Hash password using Web Crypto API (same as SonicJS AuthManager)
    const passwordHash = await hashPassword('sonicjs!')
    const now = new Date()
    const odid = `admin-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

    // Create admin user directly via SQL (bypass Drizzle schema mismatch)
    const nowSec = Math.floor(now.getTime() / 1000)
    await env.DB.prepare(`
      INSERT INTO auth_user (
        id, email, first_name, last_name, role, is_active, created_at, updated_at, name
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      odid,
      'admin@sonicjs.com',
      'Admin',
      'User',
      'admin',
      1,
      nowSec,
      nowSec,
      'Admin User'
    ).run()

    // Create auth_account record for password credential
    await env.DB.prepare(`
      INSERT INTO auth_account (id, user_id, account_id, provider_id, password, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(),
      odid,
      odid,
      'credential',
      passwordHash,
      nowSec,
      nowSec
    ).run()

    // Assign admin RBAC role (required for portal access). RBAC is document-backed
    // (services/rbac.ts): register the rbac doc types, seed system roles/verbs, then
    // assign. Idempotent and self-sufficient (works on a fresh DB before app bootstrap).
    await bootstrapDocumentTypes(env.DB)
    const rbac = new RbacService(env.DB)
    await rbac.ensureSystemRbacSeed()
    await rbac.addUserRoleByName(odid, 'admin')

    console.log('✓ Admin user created successfully')
    console.log(`  Email: admin@sonicjs.com`)
    console.log(`  Role: admin`)
    console.log('')
    console.log('You can now login at: http://localhost:8787/auth/login')
  } catch (error) {
    console.error('❌ Error creating admin user:', error)
    await dispose()
    process.exit(1)
  }

  // Clean up the platform proxy
  await dispose()
}

// Run seed
seed()
  .then(() => {
    console.log('')
    console.log('✓ Seeding complete')
    process.exit(0)
  })
  .catch((error) => {
    console.error('❌ Seeding failed:', error)
    process.exit(1)
  })
