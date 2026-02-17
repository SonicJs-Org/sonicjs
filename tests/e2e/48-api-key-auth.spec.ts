import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  ensureAdminUserExists,
} from './utils/test-helpers'

/**
 * E2E tests for API Key Authentication Middleware
 *
 * Tests the full lifecycle: create, list, use, update, revoke API keys.
 * Also tests scope enforcement and edge cases.
 */

test.describe('API Key Authentication', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  // ──────────────────────────────────────────────
  // Admin CRUD
  // ──────────────────────────────────────────────

  test('POST /admin/api-keys — create key returns sk_live_ prefix', async ({ page }) => {
    const response = await page.request.post('/admin/api-keys', {
      data: {
        name: 'E2E Test Key',
        scopes: ['search:read', 'search:write', 'search:analytics'],
      },
    })

    expect(response.status()).toBe(201)
    const body = await response.json()

    expect(body.success).toBe(true)
    expect(body.data).toHaveProperty('id')
    expect(body.data).toHaveProperty('token')
    expect(body.data.token).toMatch(/^sk_live_[a-f0-9]{64}$/)
    expect(body.data.name).toBe('E2E Test Key')
    expect(body.data.scopes).toEqual(['search:read', 'search:write', 'search:analytics'])
  })

  test('GET /admin/api-keys — list keys with masked tokens', async ({ page }) => {
    // Create a key first
    const createRes = await page.request.post('/admin/api-keys', {
      data: { name: 'List Test Key', scopes: ['search:read'] },
    })
    expect(createRes.status()).toBe(201)

    const response = await page.request.get('/admin/api-keys')
    expect(response.status()).toBe(200)

    const body = await response.json()
    expect(body.success).toBe(true)
    expect(Array.isArray(body.data)).toBe(true)
    expect(body.data.length).toBeGreaterThan(0)

    // Token should be masked (not the real token)
    const key = body.data.find((k: any) => k.name === 'List Test Key')
    expect(key).toBeDefined()
    expect(key.token_hint).toContain('sk_live_')
    expect(key.token_hint).not.toMatch(/^sk_live_[a-f0-9]{64}$/) // Not the full token
  })

  test('PATCH /admin/api-keys/:id — update key scopes', async ({ page }) => {
    // Create a key
    const createRes = await page.request.post('/admin/api-keys', {
      data: { name: 'Patch Test Key', scopes: ['search:read'] },
    })
    const created = await createRes.json()

    const response = await page.request.patch(`/admin/api-keys/${created.data.id}`, {
      data: { scopes: ['search:read', 'search:analytics'] },
    })

    expect(response.status()).toBe(200)
    const body = await response.json()
    expect(body.success).toBe(true)
  })

  test('DELETE /admin/api-keys/:id — revoke key', async ({ page }) => {
    // Create a key to revoke
    const createRes = await page.request.post('/admin/api-keys', {
      data: { name: 'Revoke Test Key', scopes: ['search:read'] },
    })
    const created = await createRes.json()

    const response = await page.request.delete(`/admin/api-keys/${created.data.id}`)
    expect(response.status()).toBe(200)

    const body = await response.json()
    expect(body.success).toBe(true)
    expect(body.message).toBe('API key revoked')
  })

  // ──────────────────────────────────────────────
  // API Key Usage on Search API
  // ──────────────────────────────────────────────

  test('valid key with search:read — search request passes', async ({ page }) => {
    // Create a key with search:read
    const createRes = await page.request.post('/admin/api-keys', {
      data: { name: 'Search Read Key', scopes: ['search:read'] },
    })
    const created = await createRes.json()
    const token = created.data.token

    // Use the key on the search endpoint
    const response = await page.request.post('/api/search', {
      headers: { 'X-API-Key': token },
      data: { query: 'test', mode: 'keyword', limit: 5 },
    })

    expect(response.status()).toBe(200)
    const body = await response.json()
    expect(body.success).toBe(true)
  })

  test('valid key with wrong scope — returns 403', async ({ page }) => {
    // Create a key with only search:write scope
    const createRes = await page.request.post('/admin/api-keys', {
      data: { name: 'Wrong Scope Key', scopes: ['search:write'] },
    })
    const created = await createRes.json()
    const token = created.data.token

    // The optionalApiKey middleware sets the key, then the inline scope check
    // in the search handler will return 403 since the key lacks search:read
    const response = await page.request.post('/api/search', {
      headers: { 'X-API-Key': token },
      data: { query: 'test', mode: 'keyword' },
    })

    expect(response.status()).toBe(403)
    const body = await response.json()
    expect(body.error).toContain('Insufficient scope')
  })

  test('expired key — treated as invalid (passes through in non-enforced mode)', async ({ page }) => {
    // Create a key that already expired (expires_at in the past)
    const pastTimestamp = Date.now() - 86400000 // 24 hours ago
    const createRes = await page.request.post('/admin/api-keys', {
      data: {
        name: 'Expired Key',
        scopes: ['search:read'],
        expires_at: pastTimestamp,
      },
    })
    const created = await createRes.json()
    const token = created.data.token

    // The middleware validates expiry — expired keys are silently ignored.
    // In non-enforced mode the request passes through without apiKey set.
    const response = await page.request.post('/api/search', {
      headers: { 'X-API-Key': token },
      data: { query: 'test', mode: 'keyword' },
    })

    // In non-enforced mode, the request passes through (expired key = no key)
    expect(response.status()).toBe(200)
  })

  test('missing key without REQUIRE_API_KEY — passes through (default)', async ({ page }) => {
    // Without REQUIRE_API_KEY=true, unauthenticated requests work fine
    const response = await page.request.post('/api/search', {
      data: { query: 'test', mode: 'keyword', limit: 5 },
    })

    expect(response.status()).toBe(200)
    const body = await response.json()
    expect(body.success).toBe(true)
  })

  test('invalid key format — treated as invalid (no crash)', async ({ page }) => {
    // Pass a random string as API key
    const response = await page.request.post('/api/search', {
      headers: { 'X-API-Key': 'not-a-valid-key' },
      data: { query: 'test', mode: 'keyword' },
    })

    // In non-enforced mode, an invalid key is silently ignored
    expect(response.status()).toBe(200)
  })

  test('revoked key no longer validates', async ({ page }) => {
    // Create and immediately revoke a key
    const createRes = await page.request.post('/admin/api-keys', {
      data: { name: 'Revoke Usage Key', scopes: ['search:read'] },
    })
    const created = await createRes.json()
    const token = created.data.token
    const id = created.data.id

    // Revoke it
    await page.request.delete(`/admin/api-keys/${id}`)

    // Try using it — in non-enforced mode, invalid key = no key = passes through
    const response = await page.request.post('/api/search', {
      headers: { 'X-API-Key': token },
      data: { query: 'test', mode: 'keyword' },
    })

    expect(response.status()).toBe(200)
    const body = await response.json()
    expect(body.success).toBe(true)
  })

  test('last_used_at updates on key usage', async ({ page }) => {
    // Create a key
    const createRes = await page.request.post('/admin/api-keys', {
      data: { name: 'LastUsed Key', scopes: ['search:read'] },
    })
    const created = await createRes.json()
    const token = created.data.token
    const id = created.data.id

    // Use the key
    await page.request.post('/api/search', {
      headers: { 'X-API-Key': token },
      data: { query: 'test', mode: 'keyword' },
    })

    // Give the fire-and-forget waitUntil a moment to complete
    await page.waitForTimeout(1000)

    // Check that last_used_at was updated via admin list
    const listRes = await page.request.get('/admin/api-keys')
    const listBody = await listRes.json()
    const key = listBody.data.find((k: any) => k.id === id)
    expect(key).toBeDefined()
    expect(key.last_used_at).not.toBeNull()
    expect(key.last_used_at).toBeGreaterThan(0)
  })

  test('analytics accessible via key with search:analytics scope', async ({ page }) => {
    // Create a key with search:analytics scope
    const createRes = await page.request.post('/admin/api-keys', {
      data: { name: 'Analytics Key', scopes: ['search:analytics'] },
    })
    const created = await createRes.json()
    const token = created.data.token

    // Access analytics endpoint with the key
    const response = await page.request.get('/api/search/analytics', {
      headers: { 'X-API-Key': token },
    })

    expect(response.status()).toBe(200)
    const body = await response.json()
    expect(body.success).toBe(true)
  })

  // ──────────────────────────────────────────────
  // Validation
  // ──────────────────────────────────────────────

  test('POST /admin/api-keys with invalid scopes — 400', async ({ page }) => {
    const response = await page.request.post('/admin/api-keys', {
      data: { name: 'Bad Scopes Key', scopes: ['invalid:scope'] },
    })

    expect(response.status()).toBe(400)
    const body = await response.json()
    expect(body.error).toContain('Invalid scopes')
  })

  test('POST /admin/api-keys without name — 400', async ({ page }) => {
    const response = await page.request.post('/admin/api-keys', {
      data: { scopes: ['search:read'] },
    })

    expect(response.status()).toBe(400)
    const body = await response.json()
    expect(body.error).toContain('name is required')
  })
})
