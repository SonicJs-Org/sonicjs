import { test, expect } from './fixtures'
import { loginAsAdmin, saveNewContent } from './utils/test-helpers'

/**
 * The content form used to arm a 30s autosave timer on every `input` and `change` event, then
 * `fetch(form.action, { method: 'POST', body: formData })` with `action=autosave` appended.
 *
 * Two things were wrong with it. `HTMLFormElement` is [LegacyOverrideBuiltIns], so the two
 * submit buttons named "action" shadowed the built-in `form.action` property: the fetch read a
 * RadioNodeList, stringified it to "[object RadioNodeList]" and posted to
 * /admin/content/[object%20RadioNodeList]. And nothing server-side has ever handled
 * `action=autosave`, so repairing the URL would have made the timer create a new document every
 * 30 seconds instead of 404ing. The timer was also re-armed on every keystroke and outlived the
 * page that set it, so it fired from whatever the editor had navigated to next.
 *
 * `/admin/content/new` is a page CI opens constantly, which made this a steady source of
 * unanswered worker requests during E2E runs. Guard the shape of the fix rather than the dead
 * code: the form writes when the operator asks it to, and never on a timer.
 *
 * `e2e_test` is code-registered and needs only title + slug.
 */
const NEW_RECORD_FORM = '/admin/content/new?collection=e2e_test'

/** Nothing on this page has a legitimate reason to schedule a write this far out. */
const LONG_TIMER_MS = 10_000

test.describe('Content form background writes @smoke @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('typing in the form arms no long-running timer and sends no write', async ({ page }) => {
    // Recorded from an init script so the wrapper is in place before any page script runs --
    // the old timer was armed by the form's own DOMContentLoaded handler.
    await page.addInitScript(() => {
      ;(window as any).__longTimers = []
      const original = window.setTimeout
      ;(window as any).setTimeout = function (handler: TimerHandler, delay?: number, ...args: any[]) {
        if (typeof delay === 'number' && delay >= 10_000) {
          ;(window as any).__longTimers.push(delay)
        }
        return original(handler, delay as any, ...args)
      }
    })

    const writes: string[] = []
    page.on('request', (req) => {
      if (req.method() !== 'GET' && req.method() !== 'HEAD') writes.push(`${req.method()} ${req.url()}`)
    })

    await page.goto(NEW_RECORD_FORM)
    await expect(page.locator('#content-form')).toBeVisible()

    const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    await page.fill('input[name="title"]', `No autosave ${stamp}`)
    await page.fill('input[name="slug"]', `no-autosave-${stamp}`)
    // `change` as well as `input`: the old handler bound both.
    await page.selectOption('select[name="status"]', 'draft')
    await page.locator('input[name="title"]').blur()

    // Long enough for the slug-availability debounce (500ms) and any immediate writer to show up.
    await page.waitForTimeout(2000)

    const timers = await page.evaluate(() => (window as any).__longTimers as number[])
    expect(timers, `the form scheduled a timer >= ${LONG_TIMER_MS}ms: ${timers.join(', ')}`).toEqual([])

    // The form itself must not have written anything yet -- nobody has pressed Save.
    expect(writes, `the form wrote without being asked: ${writes.join(', ')}`).toEqual([])
  })

  test('the explicit save posts to the collection endpoint, not to a stringified node list', async ({
    page,
  }) => {
    const seen: string[] = []
    page.on('request', (req) => {
      if (req.method() === 'POST') seen.push(new URL(req.url()).pathname)
    })

    await page.goto(NEW_RECORD_FORM)
    const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    await page.fill('input[name="title"]', `Explicit save ${stamp}`)
    await page.fill('input[name="slug"]', `explicit-save-${stamp}`)
    await page.selectOption('select[name="status"]', 'draft')

    const editPath = await saveNewContent(page, () =>
      page
        .locator('button[type="submit"]')
        .filter({ hasText: /Save|Create/ })
        .first()
        .click()
    )
    expect(editPath).toMatch(/^\/admin\/content\/[^/]+\/edit$/)

    expect(seen).toContain('/admin/content')
    // The property `form.action` resolves to the two buttons named "action" on this form, so any
    // code that reads it instead of the attribute ends up here.
    for (const path of seen) {
      expect(path, `posted to a stringified DOM node: ${path}`).not.toContain('[object')
    }
  })
})
