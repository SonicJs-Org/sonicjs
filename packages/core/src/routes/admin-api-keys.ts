/**
 * Admin API Key Management Routes
 *
 * CRUD endpoints for managing API keys.
 * All routes require admin authentication.
 */

import { Hono } from 'hono'
import type { Bindings, Variables } from '../app'
import { requireAuth } from '../middleware/auth'
import { hashApiKey, VALID_SCOPES } from '../middleware/api-key'

const adminApiKeyRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// All routes require admin auth
adminApiKeyRoutes.use('*', requireAuth())

// ────────────────────────────────────────────────────────────────
// POST /admin/api-keys — Create a new API key
// ────────────────────────────────────────────────────────────────
adminApiKeyRoutes.post('/', async (c) => {
  try {
    const body = await c.req.json()
    const { name, scopes, expires_at: expiresAt } = body

    if (!name || typeof name !== 'string') {
      return c.json({ error: 'name is required' }, 400)
    }

    if (!Array.isArray(scopes) || scopes.length === 0) {
      return c.json({ error: 'scopes array is required' }, 400)
    }

    const invalidScopes = scopes.filter((s: string) => !VALID_SCOPES.includes(s))
    if (invalidScopes.length > 0) {
      return c.json({ error: `Invalid scopes: ${invalidScopes.join(', ')}` }, 400)
    }

    // Generate token: sk_live_ + 64 hex chars (32 random bytes)
    const randomBytes = new Uint8Array(32)
    crypto.getRandomValues(randomBytes)
    const hex = Array.from(randomBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    const plainToken = `sk_live_${hex}`

    // Hash for storage
    const tokenHash = await hashApiKey(plainToken)

    const id = crypto.randomUUID()
    const user = c.get('user') as any
    const userId = user?.userId || 'system'

    const db = c.env.DB

    // Handle expires_at: can be ms timestamp or ISO string
    let expiresAtValue: string | null = null
    if (expiresAt) {
      if (typeof expiresAt === 'number') {
        expiresAtValue = new Date(expiresAt).toISOString()
      } else {
        expiresAtValue = String(expiresAt)
      }
    }

    await db
      .prepare(
        `INSERT INTO api_tokens (id, name, token, user_id, permissions, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(id, name, tokenHash, userId, JSON.stringify(scopes), expiresAtValue)
      .run()

    return c.json(
      {
        success: true,
        data: {
          id,
          name,
          token: plainToken, // shown once
          scopes,
          expires_at: expiresAtValue,
          created_at: new Date().toISOString(),
        },
      },
      201
    )
  } catch (error) {
    console.error('Create API key error:', error)
    return c.json({ error: 'Failed to create API key' }, 500)
  }
})

// ────────────────────────────────────────────────────────────────
// GET /admin/api-keys — List all keys (tokens masked)
// ────────────────────────────────────────────────────────────────
adminApiKeyRoutes.get('/', async (c) => {
  try {
    const db = c.env.DB
    const rows = await db
      .prepare(
        'SELECT id, name, token, user_id, permissions, expires_at, last_used_at, created_at FROM api_tokens ORDER BY created_at DESC'
      )
      .all()

    const keys = (rows.results || []).map((row: any) => {
      // Mask the stored hash — show "sk_live_...last8"
      const hash = row.token || ''
      const tokenHint = `sk_live_...${hash.slice(-8)}`

      let scopes: string[] = []
      try {
        scopes = JSON.parse(row.permissions)
      } catch {
        scopes = []
      }

      return {
        id: row.id,
        name: row.name,
        token_hint: tokenHint,
        scopes,
        user_id: row.user_id,
        expires_at: row.expires_at,
        last_used_at: row.last_used_at,
        created_at: row.created_at,
      }
    })

    return c.json({ success: true, data: keys })
  } catch (error) {
    console.error('List API keys error:', error)
    return c.json({ error: 'Failed to list API keys' }, 500)
  }
})

// ────────────────────────────────────────────────────────────────
// PATCH /admin/api-keys/:id — Update name or scopes
// ────────────────────────────────────────────────────────────────
adminApiKeyRoutes.patch('/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const body = await c.req.json()
    const db = c.env.DB

    // Check key exists
    const existing = await db
      .prepare('SELECT id FROM api_tokens WHERE id = ?')
      .bind(id)
      .first() as { id: string } | null

    if (!existing) {
      return c.json({ error: 'API key not found' }, 404)
    }

    const updates: string[] = []
    const values: any[] = []

    if (body.name !== undefined) {
      updates.push('name = ?')
      values.push(body.name)
    }

    if (body.scopes !== undefined) {
      if (!Array.isArray(body.scopes)) {
        return c.json({ error: 'scopes must be an array' }, 400)
      }
      const invalid = body.scopes.filter((s: string) => !VALID_SCOPES.includes(s))
      if (invalid.length > 0) {
        return c.json({ error: `Invalid scopes: ${invalid.join(', ')}` }, 400)
      }
      updates.push('permissions = ?')
      values.push(JSON.stringify(body.scopes))
    }

    if (updates.length === 0) {
      return c.json({ error: 'No fields to update' }, 400)
    }

    values.push(id) // WHERE id = ?
    await db
      .prepare(`UPDATE api_tokens SET ${updates.join(', ')} WHERE id = ?`)
      .bind(...values)
      .run()

    return c.json({ success: true })
  } catch (error) {
    console.error('Update API key error:', error)
    return c.json({ error: 'Failed to update API key' }, 500)
  }
})

// ────────────────────────────────────────────────────────────────
// DELETE /admin/api-keys/:id — Revoke (delete) a key
// ────────────────────────────────────────────────────────────────
adminApiKeyRoutes.delete('/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const db = c.env.DB

    const existing = await db
      .prepare('SELECT id, token FROM api_tokens WHERE id = ?')
      .bind(id)
      .first() as { id: string; token: string } | null

    if (!existing) {
      return c.json({ error: 'API key not found' }, 404)
    }

    await db.prepare('DELETE FROM api_tokens WHERE id = ?').bind(id).run()

    // Purge KV cache
    const kv = (c.env as any).CACHE_KV
    if (kv && existing.token) {
      try {
        await kv.delete(`apikey:${existing.token}`)
      } catch {
        // best-effort
      }
    }

    return c.json({ success: true, message: 'API key revoked' })
  } catch (error) {
    console.error('Revoke API key error:', error)
    return c.json({ error: 'Failed to revoke API key' }, 500)
  }
})

export { adminApiKeyRoutes }
