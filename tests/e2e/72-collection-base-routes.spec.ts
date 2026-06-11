import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

const BASE = process.env.BASE_URL || 'http://localhost:8787'

test.describe('per-collection base routes', () => {
  test('GET /api/:collection returns list of published items', async ({ request }) => {
    const response = await request.get(`${BASE}/api/blog_post`)
    expect(response.ok()).toBeTruthy()
    const body = await response.json()
    expect(Array.isArray(body.data)).toBe(true)
    expect(body.meta).toBeDefined()
    expect(typeof body.meta.count).toBe('number')
  })

  test('GET /api/:collection returns 404 for unknown collection', async ({ request }) => {
    const response = await request.get(`${BASE}/api/does_not_exist_collection_xyz`)
    expect(response.status()).toBe(404)
    const body = await response.json()
    expect(body.error).toBeDefined()
  })

  test('GET /api/:collection/:id returns 404 for unknown id', async ({ request }) => {
    const response = await request.get(`${BASE}/api/blog_post/nonexistent-id-xyz`)
    expect(response.status()).toBe(404)
  })

  test('GET /api/:collection does not conflict with /api/collections', async ({ request }) => {
    const response = await request.get(`${BASE}/api/collections`)
    expect(response.ok()).toBeTruthy()
    const body = await response.json()
    expect(Array.isArray(body.data)).toBe(true)
  })

  test('GET /api/:collection does not conflict with /api/content', async ({ request }) => {
    const response = await request.get(`${BASE}/api/content`)
    expect(response.ok()).toBeTruthy()
    const body = await response.json()
    expect(Array.isArray(body.data)).toBe(true)
  })

  test('GET /api/:collection supports limit query param', async ({ request }) => {
    const response = await request.get(`${BASE}/api/blog_post?limit=1`)
    expect(response.ok()).toBeTruthy()
    const body = await response.json()
    expect(body.data.length).toBeLessThanOrEqual(1)
  })

  test('POST /api/:collection requires auth', async ({ request }) => {
    const response = await request.post(`${BASE}/api/blog_post`, {
      data: { title: 'Unauthorized Test' }
    })
    expect([401, 403]).toContain(response.status())
  })

  test('POST then GET single item via /api/:collection/:id', async ({ page, request }) => {
    await loginAsAdmin(page)
    const cookies = await page.context().cookies()
    const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join('; ')

    const createRes = await request.post(`${BASE}/api/blog_post`, {
      data: { title: 'E2E Collection Route Test', status: 'published' },
      headers: { Cookie: cookieHeader }
    })
    expect(createRes.status()).toBe(201)
    const created = await createRes.json()
    const id = created.data?.id
    expect(id).toBeTruthy()

    const getRes = await request.get(`${BASE}/api/blog_post/${id}`)
    expect(getRes.ok()).toBeTruthy()
    const fetched = await getRes.json()
    expect(fetched.data.id).toBe(id)
    expect(fetched.data.title).toBe('E2E Collection Route Test')

    // cleanup
    await request.delete(`${BASE}/api/blog_post/${id}`, {
      headers: { Cookie: cookieHeader }
    })
  })

  test('PUT /api/:collection/:id updates item', async ({ page, request }) => {
    await loginAsAdmin(page)
    const cookies = await page.context().cookies()
    const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join('; ')

    const createRes = await request.post(`${BASE}/api/blog_post`, {
      data: { title: 'Update Test Original', status: 'draft' },
      headers: { Cookie: cookieHeader }
    })
    expect(createRes.status()).toBe(201)
    const id = (await createRes.json()).data?.id

    const putRes = await request.put(`${BASE}/api/blog_post/${id}`, {
      data: { title: 'Update Test Modified' },
      headers: { Cookie: cookieHeader }
    })
    expect(putRes.ok()).toBeTruthy()
    const updated = await putRes.json()
    expect(updated.data.title).toBe('Update Test Modified')

    // cleanup
    await request.delete(`${BASE}/api/blog_post/${id}`, {
      headers: { Cookie: cookieHeader }
    })
  })

  test('DELETE /api/:collection/:id removes item', async ({ page, request }) => {
    await loginAsAdmin(page)
    const cookies = await page.context().cookies()
    const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join('; ')

    const createRes = await request.post(`${BASE}/api/blog_post`, {
      data: { title: 'Delete Test Item', status: 'draft' },
      headers: { Cookie: cookieHeader }
    })
    expect(createRes.status()).toBe(201)
    const id = (await createRes.json()).data?.id

    const delRes = await request.delete(`${BASE}/api/blog_post/${id}`, {
      headers: { Cookie: cookieHeader }
    })
    expect(delRes.ok()).toBeTruthy()

    const getRes = await request.get(`${BASE}/api/blog_post/${id}`)
    expect(getRes.status()).toBe(404)
  })

  test('PUT /api/:collection/:id returns 404 for wrong collection', async ({ page, request }) => {
    await loginAsAdmin(page)
    const cookies = await page.context().cookies()
    const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join('; ')

    // Use an id that doesn't exist in this collection
    const putRes = await request.put(`${BASE}/api/blog_post/nonexistent-id-xyz`, {
      data: { title: 'Should 404' },
      headers: { Cookie: cookieHeader }
    })
    expect(putRes.status()).toBe(404)
  })
})
