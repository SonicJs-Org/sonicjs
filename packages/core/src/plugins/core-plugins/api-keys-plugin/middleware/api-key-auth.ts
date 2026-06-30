import type { Context, Next } from 'hono'
import { ApiKeyService } from '../services/api-key-service'

/**
 * API-key authentication middleware.
 *
 * Runs app-wide, right after the Better Auth session middleware. If no session
 * already resolved a user, it accepts a programmatic key from `x-api-key` or
 * `Authorization: Bearer sk_…` and sets `c.get('user')` so the existing
 * requireAuth/requireRole/requireRbac guards work unchanged.
 *
 * Wired in app.ts (like the security-audit middleware) rather than via a plugin
 * hook, because app-wide middleware ordering is owned by core. It is always-on
 * for the compiled core build — not gated on a DB plugin-active flag, since core
 * plugins aren't seeded active on a fresh install and gating would silently break
 * key auth out of the box. The lookup only runs when a request both lacks a
 * session AND presents a key header, so normal traffic pays nothing.
 */
export function apiKeyAuthMiddleware() {
  return async (c: Context, next: Next): Promise<void> => {
    if (!c.get('user')) {
      const authz = c.req.header('authorization') || ''
      const bearer = authz.toLowerCase().startsWith('bearer ') ? authz.slice(7).trim() : ''
      const presented = c.req.header('x-api-key') || (bearer.startsWith('sk_') ? bearer : '')
      if (presented) {
        try {
          const tenantId = (c.get('tenantId') as string) || 'default'
          const resolved = await new ApiKeyService(c.env.DB, tenantId).resolve(presented)
          if (resolved) {
            c.set('user', {
              userId: resolved.userId,
              email: resolved.email,
              role: resolved.role,
              isSuperAdmin: resolved.isSuperAdmin,
              // API keys are stateless bearer creds — no session window.
              exp: 0,
              iat: 0,
            })
          }
        } catch {
          // Invalid/garbled key — leave unauthenticated.
        }
      }
    }
    await next()
  }
}
