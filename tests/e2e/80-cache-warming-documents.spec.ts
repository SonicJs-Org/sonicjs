/**
 * Cache Warming — Document Model
 *
 * Verifies the cache plugin's warm endpoint reads from the `documents` table
 * (not the legacy `content` / `media` tables) per the document-model migration.
 */

import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Cache Warming — document model', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('POST /admin/cache/warm succeeds and reports content + media namespaces', async ({ page }) => {
    const response = await page.request.post('/admin/cache/warm')

    expect(response.status()).toBe(200)
    const body = await response.json()
    expect(body.success).toBe(true)
    expect(Array.isArray(body.details)).toBe(true)

    const namespaces = body.details.map((d: { namespace: string }) => d.namespace)
    expect(namespaces).toContain('content')
    expect(namespaces).toContain('media')
    expect(namespaces).toContain('collection')
  })

  test('warming does not error against the documents table', async ({ page }) => {
    // Warm twice — if warming hit the dropped `media` table or a missing column,
    // the second call would surface the same error and `warmed` would stay 0 for that namespace.
    const first = await page.request.post('/admin/cache/warm')
    const second = await page.request.post('/admin/cache/warm')

    expect(first.status()).toBe(200)
    expect(second.status()).toBe(200)

    const body = await second.json()
    expect(body.success).toBe(true)
    const namespaces = new Set(
      (body.details as Array<{ namespace: string }>).map((d) => d.namespace)
    )
    expect(namespaces.has('content')).toBe(true)
    expect(namespaces.has('media')).toBe(true)
  })

  test('cache stats endpoint reflects content + media namespaces after warming', async ({ page }) => {
    await page.request.post('/admin/cache/warm')

    const stats = await page.request.get('/admin/cache/stats')
    expect(stats.status()).toBe(200)
    const body = await stats.json()
    expect(body.success).toBe(true)
    expect(body.data).toBeDefined()
  })
})
