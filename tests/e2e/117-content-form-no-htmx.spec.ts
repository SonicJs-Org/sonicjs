import { test, expect, Page } from './fixtures'
import { fillHiddenEditorFields, loginAsAdmin } from './utils/test-helpers'

/**
 * The content form has to survive a submit that htmx did not intercept.
 *
 * htmx is loaded from a CDN, so there is a window after the markup is interactive in which
 * `hx-post` / `hx-put` are not wired up yet — and if the CDN is unreachable the window never
 * closes. The form carried no `method` or `action`, so a submit in that state fell back to the
 * browser default: a GET of the current URL with every field in the query string. For a create
 * that landed back on the "pick a collection" page and silently dropped the content; for an
 * edit it reloaded the editor with the changes gone. The form now declares `method="post"`
 * plus an `action`, and the update handler answers POST as well as PUT because a plain form
 * cannot send PUT.
 *
 * Blocking the htmx script reproduces that state exactly.
 */
test.describe('Content form submits without htmx @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
    await page.route('**/htmx*', (route) => route.abort())
  })

  test('creates and updates content with htmx unavailable', async ({ page }) => {
    // Use whichever collection the install lists first — the fallback is not collection
    // specific, and hard-coding one breaks as soon as the demo app changes.
    await page.goto('/admin/content/new')
    const collectionLink = page.locator('a[href*="/admin/content/new?collection="]').first()
    await expect(collectionLink).toBeVisible({ timeout: 15000 })
    const href = await collectionLink.getAttribute('href')
    const collectionId = new URL(`http://x${href}`).searchParams.get('collection')
    expect(collectionId).toBeTruthy()

    const timestamp = Date.now()
    const title = `E2E no-htmx ${timestamp}`

    await page.goto(`/admin/content/new?collection=${collectionId}`)
    await expect(page.locator('form#content-form')).toHaveAttribute('action', '/admin/content')
    await expect(page.locator('form#content-form')).toHaveAttribute('method', /post/i)

    await page.locator('input[name="title"]').first().fill(title)
    await page.locator('input[name="slug"]').first().fill(`e2e-no-htmx-${timestamp}`)
    await fillRequiredFields(page, timestamp)

    // Without htmx this is a plain browser submit, so it navigates.
    await Promise.all([
      page.waitForURL(/\/admin\/content\/[^/]+\/edit/, { timeout: 20000 }),
      page.locator('button[name="action"][value="save"]').first().click(),
    ])

    const rootId = page.url().match(/\/admin\/content\/([^/?]+)\/edit/)?.[1]
    expect(rootId).toBeTruthy()
    await expect(page.locator('input[name="title"]').first()).toHaveValue(title)

    // The edit form points its native action at the POST alias for the update handler.
    await expect(page.locator('form#content-form')).toHaveAttribute(
      'action',
      `/admin/content/${rootId}`
    )

    const updatedTitle = `E2E no-htmx updated ${timestamp}`
    await page.locator('input[name="title"]').first().fill(updatedTitle)
    await Promise.all([
      page.waitForURL(/\/admin\/content\/[^/]+\/edit\?success=/, { timeout: 20000 }),
      page.locator('button[name="action"][value="save"]').first().click(),
    ])

    await page.goto(`/admin/content/${rootId}/edit`)
    await expect(page.locator('input[name="title"]').first()).toHaveValue(updatedTitle)
  })
})

/**
 * Fill whatever else the collection declares required. Which fields those are is a per-
 * collection decision, so they are discovered from the rendered form rather than listed here.
 */
async function fillRequiredFields(page: Page, timestamp: number) {
  const controls = page.locator('form#content-form [required]:not([type="hidden"]):not([disabled])')

  for (let i = 0; i < (await controls.count()); i++) {
    const control = controls.nth(i)
    if (!(await control.isVisible())) continue

    const tag = (await control.evaluate((node) => node.tagName)).toLowerCase()
    if (tag === 'select') {
      const values = await control
        .locator('option')
        .evaluateAll((options) => options.map((o) => (o as HTMLOptionElement).value).filter(Boolean))
      if (values.length > 0) await control.selectOption(values[0])
      continue
    }

    if (await control.inputValue()) continue
    await control.fill(`E2E ${timestamp}`)
  }

  // Lexical — the default richtext editor on a fresh install — edits a contenteditable surface
  // and mirrors into a hidden input, so `[required]:not([type="hidden"])` never sees it. The
  // browser raises no constraint error either, and the save fails server-side instead
  // ("Content is required"), which looks like a broken form rather than an unfilled field.
  await fillHiddenEditorFields(page, `E2E no-htmx body ${timestamp}`)
}
