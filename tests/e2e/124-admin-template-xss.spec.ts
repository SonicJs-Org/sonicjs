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
    // Assert rather than skip: the seed guarantees content, so an empty list is a real failure.
    expect(id, 'seeded content is required to open a content edit page').toBeTruthy()

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

/**
 * The plugin-settings escape (`escapeHtmlAttr` on the generic string branch) sits on a path whose
 * values are `any` — seeded verbatim from a manifest's `defaultSettings`. `ai-search` ships two
 * empty arrays, so an unguarded escape helper throws and 500s the detail page. Tagged @plugins so
 * a change under templates/pages (which otherwise selects @smoke only) still gets this checked.
 */
test.describe('Plugin settings page renders non-string settings @smoke @plugins', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('ai-search detail page renders instead of 500ing on array-valued settings', async ({ page }) => {
    const res = await page.goto('/admin/plugins/ai-search')
    expect(res?.status(), 'plugin detail page must not 500').toBe(200)

    const html = await page.content()
    expect(html).not.toContain('Internal server error')
    await expect(page.getByRole('heading', { name: /AI Search/i }).first()).toBeVisible()
  })
})
