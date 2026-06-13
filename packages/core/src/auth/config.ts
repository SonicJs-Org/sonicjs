/**
 * Better Auth configuration for SonicJS — via the better-auth-cloudflare shim.
 *
 * A fresh auth instance is built per request (Workers lifecycle). The existing
 * `auth_user` table is used as Better Auth's user model. Legacy SonicJS PBKDF2
 * hashes are verified and transparently upgraded to scrypt on first login. KV
 * (CACHE_KV) is used as session secondary storage so getSession does not hit D1
 * on every request.
 *
 * Extend via config.auth.extendBetterAuth in createSonicJSApp() to add social
 * providers, magic link, 2FA, etc.
 */
/** Send an email via the SonicJS email plugin (Resend).
 *  Loads apiKey/fromEmail/fromName from the `plugins` table at runtime.
 *  Falls back to console.log when the plugin is unconfigured (local dev). */
async function sendViaEmailPlugin(
  db: D1Database,
  to: string,
  subject: string,
  html: string
): Promise<void> {
  try {
    const row = (await db
      .prepare("SELECT settings FROM plugins WHERE id = 'email'")
      .first()) as { settings: string } | null
    if (row?.settings) {
      const { apiKey, fromEmail, fromName } = JSON.parse(row.settings) as {
        apiKey?: string; fromEmail?: string; fromName?: string
      }
      if (apiKey && fromEmail) {
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: `${fromName ?? 'SonicJS'} <${fromEmail}>`,
            to: [to],
            subject,
            html,
          }),
        })
        return
      }
    }
  } catch { /* fall through to dev log */ }
  console.log(`[email-dev] To:${to} | Subject:${subject}`)
}

import { betterAuth } from 'better-auth'
import { withCloudflare } from 'better-auth-cloudflare'
import { hashPassword as baHashPassword, verifyPassword as baVerifyPassword } from 'better-auth/crypto'
import { APIError } from 'better-auth/api'
import { magicLink } from 'better-auth/plugins/magic-link'
import { emailOTP } from 'better-auth/plugins/email-otp'
import { organization } from 'better-auth/plugins/organization'
import { drizzle } from 'drizzle-orm/d1'
import { authUser, authSession, authAccount, authVerification, authTenant, authTenantMember, authTenantInvitation, authTenantTeam } from '../db/schema'
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
export function getDefaultAuthOptions(env: Bindings, requestBaseURL?: string) {
  const db = drizzle(env.DB)

  return {
    secret: env.BETTER_AUTH_SECRET,
    baseURL: env.BETTER_AUTH_URL || requestBaseURL,
    appName: 'SonicJS',
    ...withCloudflare(
      {
        autoDetectIpAddress: true,
        geolocationTracking: false,
        cf: {},
        d1: {
          db,
          options: {
            // Keys MUST match modelName values — BA resolves by modelName, not by JS variable name.
            schema: { auth_user: authUser, auth_session: authSession, auth_account: authAccount, auth_verification: authVerification, auth_tenant: authTenant, auth_tenant_member: authTenantMember, auth_tenant_invitation: authTenantInvitation, auth_tenant_team: authTenantTeam },
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
                  await env.DB.prepare(
                    "UPDATE auth_account SET password = ?, updated_at = ? WHERE password = ? AND provider_id = 'credential'"
                  )
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
          modelName: 'auth_user',
          // Field-mapping values are Drizzle *property keys* (camelCase), which
          // already match Better Auth's defaults for emailVerified/createdAt/
          // updatedAt. Only `image` differs (SonicJS uses `avatar`).
          fields: {
            image: 'avatar',
          },
          additionalFields: {
            role: { type: 'string', required: false, defaultValue: 'viewer', input: false },
            firstName: { type: 'string', required: false, defaultValue: '', input: true },
            lastName: { type: 'string', required: false, defaultValue: '', input: true },
            isSuperAdmin: { type: 'boolean', required: false, defaultValue: false, input: false },
          },
        },
        session: {
          modelName: 'auth_session',
          // Drizzle property keys already match Better Auth defaults (userId,
          // expiresAt, ipAddress, …) — no field overrides needed.
          expiresIn: 60 * 60 * 24 * 7, // 7 days
          updateAge: 60 * 60 * 24, // refresh once per day
        },
        account: { modelName: 'auth_account' },
        verification: { modelName: 'auth_verification' },
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
                  name?: string; email?: string; firstName?: string; lastName?: string
                }
                const name = (d.name ?? 'User').toString()
                const parts = name.trim().split(/\s+/)
                // Prefer explicitly-provided fields (registration form); fall back
                // to values derived from name/email.
                const firstName = d.firstName || parts[0] || 'User'
                const lastName = d.lastName || parts.slice(1).join(' ') || firstName
                return { data: { ...userData, name, firstName, lastName, role: 'viewer' } }
              },
              after: async (user: { id: string }) => {
                // Assign dynamic RBAC membership. The first real user receives
                // Administrator so fresh installs can enter the portal; later
                // self-registered users receive Viewer.
                try {
                  // RBAC roles/assignments are document-backed (services/rbac.ts).
                  // First real portal admin → Administrator; later users → Viewer.
                  // setUserRoles (via addUserRoleByName) also projects auth_user.role.
                  const { RbacService } = await import('../services/rbac')
                  const rbac = new RbacService(env.DB)
                  const roleName = (await rbac.countPortalAdmins(user.id)) === 0 ? 'admin' : 'viewer'
                  await rbac.addUserRoleByName(user.id, roleName)
                } catch {
                  /* rbac docs may not be seeded yet on older schemas — non-fatal */
                }
              },
            },
          },
        },
      }
    ),

    // ── Phase 4: BA-native login methods ─────────────────────────────────────
    // Magic-link and Email-OTP replace the standalone SonicJS plugins that
    // minted JWT cookies. Social providers replace the bespoke oauth-providers
    // plugin. All are gated on the relevant env vars / email service config
    // so they activate only when configured.

    plugins: [
      // Magic-link passwordless auth. Sends a one-time link to the user's inbox;
      // the link resolves to a BA session. Requires a working email service.
      magicLink({
        sendMagicLink: async ({ email, url }: { email: string; url: string }, _request: any) => {
          await sendViaEmailPlugin(
            env.DB, email,
            'Your sign-in link',
            `<div style="font-family:sans-serif;max-width:600px">
              <h2>Sign in to SonicJS</h2>
              <p>Click the link below to sign in. Expires in 15 minutes.</p>
              <p><a href="${url}" style="background:#465FFF;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none">Sign in</a></p>
              <p style="color:#666;font-size:12px">Or copy: ${url}</p>
            </div>`
          )
        },
        expiresIn: 15 * 60,
      }),

      // Email OTP — 6-digit code sent to inbox. Replaces the otp-login-plugin.
      emailOTP({
        sendVerificationOTP: async (params: { email: string; otp: string; type: string }, _request: any) => {
          await sendViaEmailPlugin(
            env.DB, params.email,
            'Your sign-in code',
            `<div style="font-family:sans-serif;max-width:600px">
              <h2>Your one-time code</h2>
              <p style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#465FFF">${params.otp}</p>
              <p style="color:#666">Expires in 10 minutes. Do not share this code.</p>
            </div>`
          )
        },
        otpLength: 6,
        expiresIn: 10 * 60,
      }),

      organization({
        schema: {
          organization: {
            modelName: 'auth_tenant',
            additionalFields: {
              status: { type: 'string', required: false, defaultValue: 'active', input: true },
              domain: { type: 'string', required: false, input: true },
              notes: { type: 'string', required: false, defaultValue: '', input: true },
            },
          },
          member: {
            modelName: 'auth_tenant_member',
            fields: { organizationId: 'tenant_id' },
          },
          invitation: {
            modelName: 'auth_tenant_invitation',
            fields: { organizationId: 'tenant_id' },
          },
          team: {
            modelName: 'auth_tenant_team',
            fields: { organizationId: 'tenant_id' },
          },
        },
      }),
    ],

    // ── Phase 4: Social providers ─────────────────────────────────────────
    // Activated when the relevant env vars are set. Replaces the bespoke
    // oauth-providers SonicJS plugin. Set via wrangler secret put / .dev.vars.
    socialProviders: {
      ...(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET
        ? { github: { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET } }
        : {}),
      ...(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET
        ? { google: { clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET } }
        : {}),
    },
  }
}

export type BetterAuthDefaultOptions = ReturnType<typeof getDefaultAuthOptions>
export type ExtendBetterAuth = (opts: BetterAuthDefaultOptions) => BetterAuthDefaultOptions

/** Create a Better Auth instance for this request. */
export function createAuth(env: Bindings, extendBetterAuth?: ExtendBetterAuth, requestBaseURL?: string) {
  // Hard-fail rather than sign sessions with an undefined/blank secret. The
  // secret must be provided via `wrangler secret put BETTER_AUTH_SECRET`
  // (prod/preview) or a gitignored `.dev.vars` (local) — never committed.
  if (!env.BETTER_AUTH_SECRET || env.BETTER_AUTH_SECRET.length < 16) {
    throw new Error(
      'BETTER_AUTH_SECRET is missing or too short. Set it as a Wrangler secret ' +
        '(wrangler secret put BETTER_AUTH_SECRET) or in a gitignored .dev.vars for local dev. ' +
        'Refusing to initialize auth without a strong signing secret.'
    )
  }
  const defaults = getDefaultAuthOptions(env, requestBaseURL)
  const options = extendBetterAuth ? extendBetterAuth(defaults) : defaults
  return betterAuth(options as Parameters<typeof betterAuth>[0])
}

export type SonicJSAuth = ReturnType<typeof createAuth>
