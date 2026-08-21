import { test, expect } from '@playwright/test'
import { loginAsAdmin, createTestContent } from './utils/test-helpers'

/**
 * Stored-XSS regression for the admin template escaping sweep.
 *
 * A content author can set a title/slug; those values are rendered into the admin content list that
 * a higher-privileged admin views. Before the escapeHtml sweep the title/slug were interpolated raw,
 * so an author could plant script that runs in an admin's session (privilege escalation). This spec
 * plants an executable payload and asserts (a) it never fires and (b) it is HTML-escaped in the DOM.
 */
test.describe('Admin template XSS escaping @content @smoke', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('stored XSS in a content title/slug is escaped, not executed, in the content list', async ({ page }) => {
    // onerror fires on render if the markup is live; a flag lets us prove it did NOT.
    const marker = `xss${Date.now()}`
    const payload = `<img src=x onerror="window.__xssFired='${marker}'">`

    // Catch any alert()/confirm() a live payload might raise — none should occur.
    let dialogSeen = false
    page.on('dialog', async (d) => {
      dialogSeen = true
      await d.dismiss()
    })

    // Payload in the title only — the slug has a format validator; slug escaping is covered by the
    // admin-templates-xss unit test.
    const created = await createTestContent(page, {
      title: `Evil ${payload}`,
      slug: `evil-${marker}`,
      content: 'stored xss probe',
    })
    expect(created, 'test content should have been created').toBe(true)

    await page.goto('/admin/content')
    await page.waitForLoadState('networkidle')

    // 1) The payload must not have executed.
    const fired = await page.evaluate(() => (window as { __xssFired?: string }).__xssFired)
    expect(fired, 'onerror payload must not execute').toBeUndefined()
    expect(dialogSeen, 'no XSS dialog should appear').toBe(false)

    // 2) There must be no live <img> injected from our payload (escaped text is inert).
    const injectedImg = await page.locator('img[src="x"]').count()
    expect(injectedImg, 'payload <img> must not become a real element').toBe(0)

    // 3) The escaped form must be present in the served HTML (proves the sink is reached + escaped).
    const html = await page.content()
    expect(html).toContain('&lt;img src=x onerror=')
    expect(html).not.toContain(`onerror="window.__xssFired='${marker}'"`)
  })
})
