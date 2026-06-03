/**
 * Better Auth configuration for SonicJS — via the better-auth-cloudflare shim.
 *
 * A fresh auth instance is built per request (Workers lifecycle). The existing
 * `users` table is reused as Better Auth's user model, so there is no FK rewrite.
 * Legacy SonicJS PBKDF2 hashes are verified and transparently upgraded to scrypt
 * on first login. KV (CACHE_KV) is used as session secondary storage so
 * getSession does not hit D1 on every request.
 *
 * Extend via config.auth.extendBetterAuth in createSonicJSApp() to add social
 * providers, magic link, 2FA, etc.
 */
import { betterAuth } from 'better-auth'
import { withCloudflare } from 'better-auth-cloudflare'
import { hashPassword as baHashPassword, verifyPassword as baVerifyPassword } from 'better-auth/crypto'
import { APIError } from 'better-auth/api'
import { drizzle } from 'drizzle-orm/d1'
import { users, session, account, verification } from '../db/schema'
import { isRegistrationEnabled, isFirstUserRegistration } from '../services/auth-validation'
import type { Bindings } from '../app'

/**
 * Verify a password against a SonicJS legacy PBKDF2 hash:
 *   pbkdf2:<iterations>:<saltHex>:<hashHex>   (PBKDF2-SHA256, 256-bit)
 * Mirrors AuthManager.verifyPassword in middleware/auth.ts.
 */
async function verifyLegacyPbkdf2(password: string, stored: string): Promise<boolean> {
  const parts = stored.split(':')
  if (parts.length !== 4) return false
  const iterations = parseInt(parts[1]!, 10)
  const saltBytes = parts[2]!.match(/.{2}/g)
  if (!saltBytes || !Number.isFinite(iterations)) return false
  const salt = new Uint8Array(saltBytes.map((b) => parseInt(b, 16)))
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, km, 256)
  const actual = Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, '0')).join('')
  const expected = parts[3]!
  if (actual.length !== expected.length) return false
  let diff = 0
  for (let i = 0; i < actual.length; i++) diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i)
  return diff === 0
}

/**
 * Build the default Better Auth options used by SonicJS (through the CF shim).
 * Exported so apps can extend via config.auth.extendBetterAuth.
 */
export function getDefaultAuthOptions(env: Bindings) {
  const db = drizzle(env.DB)

  return {
    secret: env.BETTER_AUTH_SECRET,
    baseURL: env.BETTER_AUTH_URL,
    appName: 'SonicJS',
    ...withCloudflare(
      {
        autoDetectIpAddress: true,
        geolocationTracking: false,
        cf: {},
        d1: {
          db,
          options: {
            // Map Better Auth models to the existing SonicJS tables. Keys must
            // match each model's resolved table name (modelName below): the user
            // model resolves to the `users` table.
            schema: { users, session, account, verification },
          },
        },
        kv: env.CACHE_KV, // session secondary storage → getSession skips D1
      },
      {
        basePath: '/auth',
        emailAndPassword: {
          enabled: true,
          autoSignIn: true,
          // Transparent migration of SonicJS legacy PBKDF2 hashes: verify against
          // the old format on login, then re-hash to scrypt and persist. No
          // mass-rehash, no forced password resets.
          password: {
            verify: async ({ hash, password }: { hash: string; password: string }) => {
              if (hash.startsWith('pbkdf2:')) {
                const ok = await verifyLegacyPbkdf2(password, hash)
                if (ok) {
                  const upgraded = await baHashPassword(password)
                  await env.DB.prepare('UPDATE account SET password = ?, updated_at = ? WHERE password = ?')
                    .bind(upgraded, Math.floor(Date.now() / 1000), hash)
                    .run()
                }
                return ok
              }
              return baVerifyPassword({ hash, password })
            },
          },
        },
        user: {
          modelName: 'users',
          // Field-mapping values are Drizzle *property keys* (camelCase), which
          // already match Better Auth's defaults for emailVerified/createdAt/
          // updatedAt. Only `image` differs (SonicJS uses `avatar`).
          fields: {
            image: 'avatar',
          },
          additionalFields: {
            role: { type: 'string', required: false, defaultValue: 'viewer', input: false },
            username: { type: 'string', required: false, defaultValue: '', input: true },
            firstName: { type: 'string', required: false, defaultValue: '', input: true },
            lastName: { type: 'string', required: false, defaultValue: '', input: true },
          },
        },
        session: {
          modelName: 'session',
          // Drizzle property keys already match Better Auth defaults (userId,
          // expiresAt, ipAddress, …) — no field overrides needed.
          expiresIn: 60 * 60 * 24 * 7, // 7 days
          updateAge: 60 * 60 * 24, // refresh once per day
        },
        account: { modelName: 'account' },
        verification: { modelName: 'verification' },
        databaseHooks: {
          user: {
            create: {
              before: async (userData: Record<string, unknown>) => {
                const isFirst = await isFirstUserRegistration(env.DB)
                if (!isFirst) {
                  const enabled = await isRegistrationEnabled(env.DB)
                  if (!enabled) {
                    throw new APIError('BAD_REQUEST', { message: 'Registration is currently disabled.' })
                  }
                }
                const d = userData as {
                  name?: string; email?: string; firstName?: string; lastName?: string; username?: string
                }
                const name = (d.name ?? 'User').toString()
                const parts = name.trim().split(/\s+/)
                const email = d.email ?? ''
                // Prefer explicitly-provided fields (registration form); fall back
                // to values derived from name/email.
                const firstName = d.firstName || parts[0] || 'User'
                const lastName = d.lastName || parts.slice(1).join(' ') || firstName
                const username = d.username || (email ? email.split('@')[0]! : `user${Math.floor(Date.now() / 1000)}`)
                return { data: { ...userData, name, firstName, lastName, username, role: 'viewer' } }
              },
              after: async (user: { id: string }) => {
                // Promote to admin when no admin exists yet (the first real user).
                // Counting admins (rather than all users) ignores internal seed
                // users like `system-forms`.
                const result = (await env.DB.prepare(
                  "SELECT COUNT(*) as count FROM users WHERE role = 'admin' AND id != ?"
                )
                  .bind(user.id)
                  .first()) as { count: number } | null
                if ((result?.count ?? 0) === 0) {
                  await env.DB.prepare("UPDATE users SET role = 'admin' WHERE id = ?").bind(user.id).run()
                }
                // Mirror the primary role into the dynamic RBAC membership table
                // so the user shows up with a role in the RBAC matrix immediately.
                try {
                  const row = (await env.DB.prepare('SELECT role FROM users WHERE id = ?')
                    .bind(user.id)
                    .first()) as { role: string } | null
                  const roleName = row?.role ?? 'viewer'
                  await env.DB.prepare(
                    'INSERT OR IGNORE INTO rbac_user_roles (user_id, role_id) SELECT ?, id FROM rbac_roles WHERE name = ?'
                  )
                    .bind(user.id, roleName)
                    .run()
                } catch {
                  /* rbac tables may not exist on older schemas — non-fatal */
                }
              },
            },
          },
        },
      }
    ),
  }
}

export type BetterAuthDefaultOptions = ReturnType<typeof getDefaultAuthOptions>
export type ExtendBetterAuth = (opts: BetterAuthDefaultOptions) => BetterAuthDefaultOptions

/** Create a Better Auth instance for this request. */
export function createAuth(env: Bindings, extendBetterAuth?: ExtendBetterAuth) {
  const defaults = getDefaultAuthOptions(env)
  const options = extendBetterAuth ? extendBetterAuth(defaults) : defaults
  return betterAuth(options as Parameters<typeof betterAuth>[0])
}

export type SonicJSAuth = ReturnType<typeof createAuth>
