import { createDb, users } from '@sonicjs-cms/core'
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
    const now = Date.now()
    const odid = `admin-${now}-${Math.random().toString(36).substr(2, 9)}`

    // Create admin user
    await db
      .insert(users)
      .values({
        id: odid,
        email: 'admin@sonicjs.com',
        username: 'admin',
        firstName: 'Admin',
        lastName: 'User',
        passwordHash: passwordHash,
        role: 'admin',
        isActive: true,
        createdAt: now,
        updatedAt: now
      })
      .run()

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
