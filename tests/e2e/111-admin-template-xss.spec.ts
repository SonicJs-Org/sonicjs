import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * XSS regression for the admin template escaping sweep.
 *
 * The content edit form reflects the `?ref=` query param (used to preserve list filters on the
 * "back to list" link) into an href AND a hidden input. Before the escapeHtml sweep it was
 * interpolated raw, so a crafted `?ref=` could break out of the attribute and inject script into an
 * admin's page. This drives that sink end-to-end: it is fully deterministic (the payload comes
 * straight from the URL we control), unlike a stored-XSS path that depends on content creation and
 * list pagination on the shared preview env. The stored content-list/media/users sinks are covered
 * exhaustively by the admin-templates-xss unit test.
 */
test.describe('Admin template XSS escaping @content @smoke', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('reflected ?ref= on the content edit page is escaped and never executes', async ({ page }) => {
    // The edit form needs a real document id; the seed guarantees a published "Welcome" post.
    const res = await page.request.get('/api/content')
    const body = await res.json().catch(() => ({} as any))
    const id: string | undefined = body?.data?.[0]?.id
    test.skip(!id, 'no existing content on the preview to open an edit page')

    const marker = `xss${Date.now()}`
    // Breaks out of a double-quoted attribute and injects an element whose onerror sets a flag.
    const payload = `x"><img src=y onerror="window.__xssFired='${marker}'">`

    let dialogSeen = false
    page.on('dialog', async (d) => {
      dialogSeen = true
      await d.dismiss()
    })

    await page.goto(`/admin/content/${id}/edit?ref=${encodeURIComponent(payload)}`)
    await page.waitForLoadState('networkidle')

    // 1) The injected onerror must never fire.
    const fired = await page.evaluate(() => (window as { __xssFired?: string }).__xssFired)
    expect(fired, 'reflected payload must not execute').toBeUndefined()
    expect(dialogSeen, 'no XSS dialog should appear').toBe(false)

    // 2) No real <img> element must have been injected from the payload (escaped text is inert).
    expect(await page.locator('img[src="y"]').count(), 'payload <img> must not become a live element').toBe(0)

    // 3) The reflection must be HTML-escaped in the served markup (proves the sink is reached + escaped).
    const html = await page.content()
    expect(html).not.toContain(`onerror="window.__xssFired='${marker}'"`)
    expect(html).toContain('&quot;&gt;&lt;img src=y onerror=')
  })
})
