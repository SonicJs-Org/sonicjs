/**
 * Cache Invalidation E2E Tests
 *
 * Validates that updating a content item actually invalidates the in-memory
 * and KV API list cache so subsequent GET requests return fresh data.
 *
 * Regression for: invalidation patterns missing `api:` namespace prefix
 * (patterns like `content-filtered:*` never matched stored keys `api:content-filtered:...:v1`)
 */

import { test, expect } from './fixtures'
import { loginAsAdmin, ADMIN_CREDENTIALS, TEST_ORIGIN } from './utils/test-helpers'
import type { APIRequestContext } from '@playwright/test'

const API = TEST_ORIGIN
// Collection slugs use underscores; `blog` is not a registered collection.
const COLLECTION = 'blog_post'

async function pollListForItem(
  request: APIRequestContext,
  itemId: string,
  { retries = 5, delayMs = 1000 } = {}
): Promise<any[]> {
  for (let i = 0; i < retries; i++) {
    const res = await request.get(`${API}/api/${COLLECTION}`)
    expect(res.status()).toBe(200)
    const items: any[] = (await res.json())?.data ?? []
    if (items.some((item) => item.id === itemId)) return items
    if (i < retries - 1) await new Promise((r) => setTimeout(r, delayMs))
  }
  const final = await request.get(`${API}/api/${COLLECTION}`)
  return (await final.json())?.data ?? []
}

test.describe('Cache invalidation — list freshness after item update @api', () => {
  test('creating item via public API invalidates list cache', async ({ request }) => {
    const loginRes = await request.post(`${API}/auth/sign-in/email`, {
      data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(loginRes.ok()).toBeTruthy()

    // Fetch list — populate cache
    const list1 = await request.get(`${API}/api/${COLLECTION}`)
    expect(list1.status()).toBe(200)
    const data1 = await list1.json()
    const idsBefore: string[] = (data1?.data ?? []).map((i: any) => i.id)

    // Create new item
    const stamp = Date.now()
    const createRes = await request.post(`${API}/api/${COLLECTION}`, {
      data: {
        title: `Cache test item ${stamp}`,
        slug: `cache-test-${stamp}`,
        data: {},
      },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(createRes.ok()).toBeTruthy()
    const createdId = (await createRes.json())?.data?.id
    expect(createdId).toBeTruthy()
    expect(idsBefore).not.toContain(createdId)

    // Fetch list again — must contain the new item, not a stale cached page.
    // Poll because Cloudflare Workers may route to a different isolate whose
    // in-memory cache has not yet been invalidated.
    const freshItems = await pollListForItem(request, createdId)
    expect(freshItems.map((i: any) => i.id)).toContain(createdId)
  })

  test('updating item via public API invalidates list cache', async ({ request }) => {
    const loginRes = await request.post(`${API}/auth/sign-in/email`, {
      data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(loginRes.ok()).toBeTruthy()

    // Create the item this test will edit, so it never depends on seeded content.
    const stamp = Date.now()
    const createRes = await request.post(`${API}/api/${COLLECTION}`, {
      data: { title: `Cache update target ${stamp}`, slug: `cache-update-${stamp}`, data: {} },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(createRes.ok()).toBeTruthy()
    const created = (await createRes.json())?.data
    expect(created?.id).toBeTruthy()

    // Prime the list cache — poll until the created item appears (cross-isolate delay).
    const primedItems = await pollListForItem(request, created.id)
    expect(primedItems.map((item: any) => item.id)).toContain(created.id)

    const newTitle = `Cache update target ${stamp} (updated)`
    const updateRes = await request.put(`${API}/api/${COLLECTION}/${created.id}`, {
      data: { title: newTitle },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(updateRes.ok()).toBeTruthy()

    // Poll until the updated title propagates across isolates.
    let updatedItem: any
    for (let i = 0; i < 5; i++) {
      const res = await request.get(`${API}/api/${COLLECTION}`)
      expect(res.status()).toBe(200)
      updatedItem = ((await res.json())?.data ?? []).find((it: any) => it.id === created.id)
      if (updatedItem?.title === newTitle) break
      if (i < 4) await new Promise((r) => setTimeout(r, 1000))
    }
    expect(updatedItem).toBeDefined()
    expect(updatedItem?.title).toBe(newTitle)
  })

  test('admin clear cache endpoint restores fresh list', async ({ page }) => {
    await loginAsAdmin(page)

    // Prime the list cache
    await page.request.get(`${API}/api/${COLLECTION}`)

    // Clear all caches via admin endpoint
    const clearRes = await page.request.post(`${API}/admin/cache/clear`)
    expect(clearRes.status()).toBe(200)
    const clearData = await clearRes.json()
    expect(clearData.success).toBe(true)

    // List should still be fetchable after clear
    const listRes = await page.request.get(`${API}/api/${COLLECTION}`)
    expect(listRes.status()).toBe(200)
  })
})
