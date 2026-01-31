/**
 * Better Auth configuration for SonicJS
 * Factory creates auth instance with runtime env (DB, secrets) for Cloudflare Workers.
 * Supports config.auth.extendBetterAuth in SonicJSConfig to add social providers, magic link, 2FA, etc.
 */

import { betterAuth } from 'better-auth'
import { drizzleAdapter } from 'better-auth/adapters/drizzle'
import { drizzle } from 'drizzle-orm/d1'
import { APIError } from 'better-auth/api'
import { users, session, account, verification } from '../db/schema'
import { isRegistrationEnabled, isFirstUserRegistration } from '../services/auth-validation'
import type { Bindings } from '../app'

/**
 * Build the default Better Auth options used by SonicJS.
 * Exported so users can extend via config.auth.extendBetterAuth in createSonicJSApp().
 */
export function getDefaultAuthOptions(env: Bindings) {
  const db = drizzle(env.DB)

  return {
    database: drizzleAdapter(db, {
      provider: 'sqlite',
      schema: {
        user: users,
        session,
        account,
        verification
      }
    }),
    basePath: '/auth',
    baseURL: env.BETTER_AUTH_URL,
    secret: env.BETTER_AUTH_SECRET,
    appName: 'SonicJS',
    emailAndPassword: {
      enabled: true,
      autoSignIn: true
    },
    user: {
      modelName: 'users',
      fields: {
        image: 'avatar',
        emailVerified: 'email_verified',
        createdAt: 'created_at',
        updatedAt: 'updated_at',
        firstName: 'first_name',
        lastName: 'last_name'
      },
      additionalFields: {
        role: {
          type: 'string',
          required: false,
          defaultValue: 'viewer',
          input: false
        },
        username: {
          type: 'string',
          required: false,
          defaultValue: '',
          input: true
        },
        firstName: {
          type: 'string',
          required: false,
          defaultValue: '',
          input: true
        },
        lastName: {
          type: 'string',
          required: false,
          defaultValue: '',
          input: true
        }
      }
    },
    session: {
      modelName: 'session',
      fields: {
        userId: 'user_id',
        expiresAt: 'expires_at',
        ipAddress: 'ip_address',
        userAgent: 'user_agent',
        createdAt: 'created_at',
        updatedAt: 'updated_at'
      },
      expiresIn: 60 * 60 * 24, // 24 hours
      updateAge: 60 * 60 * 24,
      storeSessionInDatabase: true
    },
    databaseHooks: {
      user: {
        create: {
          before: async (userData: Record<string, unknown>, _ctx: unknown) => {
            const d1 = env.DB
            const isFirst = await isFirstUserRegistration(d1)
            if (!isFirst) {
              const enabled = await isRegistrationEnabled(d1)
              if (!enabled) {
                throw new APIError('BAD_REQUEST', {
                  message: 'Registration is currently disabled.'
                })
              }
            }
            const name = ((userData as { name?: string }).name ?? 'User') as string
            const parts = name.trim().split(/\s+/)
            const firstName = parts[0] ?? 'User'
            const lastName = parts.slice(1).join(' ') || firstName
            const email = (userData as { email?: string }).email ?? ''
            const username = email ? email.split('@')[0]! : `user${Date.now()}`
            return {
              data: {
                ...userData,
                name,
                firstName,
                lastName,
                username,
                role: 'viewer'
              } as typeof userData
            }
          },
          after: async (user: { id: string }, _ctx: unknown) => {
            const d1 = env.DB
            const result = (await d1
              .prepare('SELECT COUNT(*) as count FROM users')
              .first()) as { count: number } | null
            const count = result?.count ?? 0
            const role = count === 1 ? 'admin' : 'viewer'
            await d1.prepare('UPDATE users SET role = ? WHERE id = ?').bind(role, user.id).run()
          }
        }
      }
    }
  }
}

export type BetterAuthDefaultOptions = ReturnType<typeof getDefaultAuthOptions>

export type ExtendBetterAuth = (defaultOptions: BetterAuthDefaultOptions) => BetterAuthDefaultOptions

/**
 * Create Better Auth instance with D1 database and SonicJS-specific hooks.
 * Pass optional extendBetterAuth (from config.auth.extendBetterAuth) to add social providers,
 * magic link, 2FA, or other login methods.
 */
export function createAuth(env: Bindings, extendBetterAuth?: ExtendBetterAuth) {
  const defaultOptions = getDefaultAuthOptions(env)
  const options = extendBetterAuth ? extendBetterAuth(defaultOptions) : defaultOptions
  return betterAuth(options as Parameters<typeof betterAuth>[0])
}

export type SonicJSAuth = ReturnType<typeof createAuth>
