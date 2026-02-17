/**
 * API Key Authentication Middleware
 *
 * Validates API keys sent via X-API-Key header.
 * Keys are stored as SHA-256 hashes in the api_tokens table.
 * Lookups are cached in KV with a 5-minute TTL.
 */

import { Context, Next } from 'hono'

export type ApiKeyContext = {
  id: string
  name: string
  scopes: string[]
  userId: string
}

const VALID_SCOPES = ['search:read', 'search:write', 'search:analytics']

/**
 * SHA-256 hash an API key token for storage / lookup.
 */
export async function hashApiKey(token: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

// ────────────────────────────────────────────────────────────────
// Internal: resolve & validate a key from the request
// ────────────────────────────────────────────────────────────────

interface TokenRow {
  id: string
  name: string
  user_id: string
  permissions: string
  expires_at: string | null
  last_used_at: string | null
}

async function resolveApiKey(c: Context): Promise<ApiKeyContext | null> {
  const header = c.req.header('X-API-Key')
  if (!header) return null

  const hash = await hashApiKey(header)

  // 1. KV cache check
  const kv = (c.env as any).CACHE_KV
  if (kv) {
    try {
      const cached = await kv.get(`apikey:${hash}`, 'json')
      if (cached) return cached as ApiKeyContext
    } catch {
      // KV miss — fall through to D1
    }
  }

  // 2. D1 lookup
  const db = (c.env as any).DB
  if (!db) return null

  let row: TokenRow | null = null
  try {
    row = await db
      .prepare('SELECT id, name, user_id, permissions, expires_at, last_used_at FROM api_tokens WHERE token = ? LIMIT 1')
      .bind(hash)
      .first() as TokenRow | null
  } catch {
    return null
  }

  if (!row) return null

  // 3. Check expiry
  if (row.expires_at) {
    const expiresMs = typeof row.expires_at === 'string'
      ? new Date(row.expires_at).getTime()
      : Number(row.expires_at)
    if (expiresMs < Date.now()) return null // expired
  }

  // 4. Parse scopes
  let scopes: string[] = []
  try {
    scopes = JSON.parse(row.permissions)
    if (!Array.isArray(scopes)) scopes = []
  } catch {
    scopes = []
  }

  const apiKey: ApiKeyContext = {
    id: row.id,
    name: row.name,
    scopes,
    userId: row.user_id,
  }

  // 5. Cache in KV (5-min TTL)
  if (kv) {
    try {
      await kv.put(`apikey:${hash}`, JSON.stringify(apiKey), { expirationTtl: 300 })
    } catch {
      // best-effort
    }
  }

  // 6. Fire-and-forget: update last_used_at
  try {
    const ctx = (c as any).executionCtx
    if (ctx?.waitUntil) {
      ctx.waitUntil(
        db
          .prepare('UPDATE api_tokens SET last_used_at = ? WHERE id = ?')
          .bind(Date.now(), row.id)
          .run()
      )
    }
  } catch {
    // best-effort
  }

  return apiKey
}

// ────────────────────────────────────────────────────────────────
// Public middleware
// ────────────────────────────────────────────────────────────────

/**
 * Require a valid API key with a specific scope.
 *
 * When `REQUIRE_API_KEY` env var is NOT set, falls back to
 * optionalApiKey() behavior (allow through, validate if present).
 */
export const requireApiKey = (scope: string) => {
  return async (c: Context, next: Next) => {
    const enforce = (c.env as any).REQUIRE_API_KEY === 'true'

    const apiKey = await resolveApiKey(c)

    if (apiKey) {
      c.set('apiKey', apiKey)
      if (!apiKey.scopes.includes(scope)) {
        return c.json({ error: `Insufficient scope. Required: ${scope}` }, 403)
      }
      return next()
    }

    // No valid key found
    if (enforce) {
      return c.json({ error: 'API key required. Pass X-API-Key header.' }, 401)
    }

    // Non-enforced: allow through
    return next()
  }
}

/**
 * Optionally validate an API key if the X-API-Key header is present.
 * Does NOT block if no key is provided.
 */
export const optionalApiKey = () => {
  return async (c: Context, next: Next) => {
    try {
      const apiKey = await resolveApiKey(c)
      if (apiKey) {
        c.set('apiKey', apiKey)
      }
    } catch {
      // Don't block on validation errors
    }
    return next()
  }
}

export { VALID_SCOPES }
