/**
 * Testimonials admin (document-backed) — E2E regression guard.
 *
 * Guards the fix that mounted /admin/testimonials (the router existed but was never wired into
 * app.ts, so the page + add form 404'd). Verifies the admin list renders and that creating a
 * testimonial through the real admin route stores a document readable via the testimonials API.
 *
 * Run locally: `npm run e2e -- 64-document-testimonials-admin`.
 */
import { test, expect } from '@playwright/test'
import { loginAsAdmin, waitForHTMX } from './utils/test-helpers'

test.describe('Testimonials admin (document-backed)', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('admin /admin/testimonials renders (router is mounted)', async ({ page }) => {
    const res = await page.goto('/admin/testimonials')
    await waitForHTMX(page)
    expect(res?.status(), '/admin/testimonials must be mounted (not 404)').toBeLessThan(400)
    await expect(page.locator('body')).toContainText(/Testimonial/i)
  })

  test('creating a testimonial via the admin route stores a document on the API', async ({ page }) => {
    const unique = await page.evaluate(() => Math.random().toString(36).slice(2, 8))
    const name = `E2E Tester ${unique}`

    // The add form posts to /admin/testimonials; drive the real route directly.
    const res = await page.request.post('/admin/testimonials', {
      multipart: {
        authorName: name,
        authorTitle: 'QA',
        authorCompany: 'Acme',
        testimonialText: 'Great product.',
        rating: '5',
        sortOrder: '1',
        isPublished: 'true',
      },
    })
    expect([200, 302]).toContain(res.status())

    // Published testimonial should be returned by the testimonials API.
    const apiRes = await page.request.get('/api/testimonials')
    expect(apiRes.ok()).toBeTruthy()
    const body = await apiRes.json()
    const list = Array.isArray(body) ? body : (body.data ?? body.testimonials ?? [])
    expect(list.some((t: any) => (t.author_name ?? t.authorName) === name), 'created testimonial should appear on the API').toBeTruthy()
  })
})
