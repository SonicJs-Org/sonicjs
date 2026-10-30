import { test, expect, type Page } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * Lexical is the default richtext editor, and `blog_post.content` is declared `type: 'lexical'`,
 * so `/admin/content/new?collection=blog_post` always renders a real editor. Every test in this
 * file used to hedge against it not being there — `if (await wrapper.count() === 0) return`,
 * nested `if`s, a `.catch(() => {})` on the init wait — so the file reported green while
 * asserting nothing about the editor at all.
 *
 * Two tests were deleted rather than hollowed out:
 *
 * - `lexical field type can be selected in collection schema editor` looked for a field-type
 *   `<select>` on `/admin/collections`. That page is a read-only list; collections are code-only
 *   (`registerCollections`), so there is no schema editor and no select to find. The test was
 *   `if (count > 0)` around its only assertion, i.e. a permanent no-op.
 * - `fallback textarea renders when lexical plugin is inactive` said so itself: "Since we can't
 *   easily deactivate the plugin in E2E, we just verify the plugin settings page is accessible."
 *   Deactivating the default editor mid-suite is shared global state that a concurrently running
 *   @content spec would see, and the fallback is a pure function of `pluginStatuses`, so it is
 *   covered in `__tests__/templates/dynamic-field-extended.test.ts` instead — where quill,
 *   mdxeditor and tinymce fallbacks already live.
 */

const BLOG_POST_FORM = '/admin/content/new?collection=blog_post'

/** The editor Lexical renders for `blog_post.content`. */
const editor = (page: Page) => page.locator('.lexical-editor-wrapper').first()

test.describe('Lexical Rich Text Editor Plugin @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('ships active on a fresh install', async ({ page }) => {
    await page.goto('/admin/plugins')

    // data-name carries the manifest's displayName, which is what the card renders.
    const card = page.locator('.plugin-card[data-name="Lexical Rich Text Editor"]')
    await expect(card).toHaveCount(1)
    await expect(card).toHaveAttribute('data-status', 'active')
    await expect(card.locator('.status-badge')).toContainText('Active')
  })

  test('renders the editor for a lexical field', async ({ page }) => {
    await page.goto(BLOG_POST_FORM)

    const wrapper = editor(page)
    await expect(wrapper).toBeVisible()
    await expect(wrapper).toHaveAttribute('data-field-id', 'field-content')

    await expect(wrapper.locator('.lexical-toolbar')).toBeVisible()

    const surface = wrapper.locator('.lexical-content-editable')
    await expect(surface).toBeVisible()
    await expect(surface).toHaveAttribute('contenteditable', 'true')
    await expect(surface).toHaveAttribute('role', 'textbox')

    // The hidden input is what the form actually submits; without it a typed post saves empty.
    await expect(wrapper.locator('input[type="hidden"][name="content"]')).toHaveCount(1)

    // These two only render when the server resolved the plugin as active, so they are the
    // server-side half of the "active by default" claim above.
    await expect(page.locator('#lexical-importmap')).toHaveCount(1)
    await expect(page.locator('#lexical-editor-styles')).toHaveCount(1)
  })

  test('renders the formatting actions the toolbar claims', async ({ page }) => {
    await page.goto(BLOG_POST_FORM)

    const toolbar = editor(page).locator('.lexical-toolbar')
    await expect(toolbar).toBeVisible()

    // bold/italic/link are in every toolbar preset, so asserting them does not pin the field to
    // one preset — it pins that the buttons the init script wires up actually exist.
    for (const action of ['bold', 'italic', 'link']) {
      await expect(
        toolbar.locator(`[data-action="${action}"]`),
        `toolbar is missing the ${action} button`
      ).toBeVisible()
    }

    // Every button must carry an action and a label: the click handler dispatches on
    // `data-action`, and a button whose only content is an icon is unreachable without the label.
    const buttons = toolbar.locator('.lexical-toolbar-btn')
    expect(await buttons.count()).toBeGreaterThan(2)
    for (const attr of ['data-action', 'aria-label']) {
      const values = await buttons.evaluateAll(
        (els, name) => els.map((el) => el.getAttribute(name as string) ?? ''),
        attr
      )
      expect(values.filter((v) => v === ''), `${attr} missing on a toolbar button`).toEqual([])
    }
  })

  test('typing fills the hidden input the form submits', async ({ page }) => {
    await page.goto(BLOG_POST_FORM)

    const wrapper = editor(page)
    await expect(wrapper).toBeVisible()

    // Lexical itself is fetched from esm.sh at runtime. Everything above is server-rendered and
    // unconditional; this test is the one part that cannot run without that fetch succeeding, so
    // it feature-detects rather than failing the suite on someone else's CDN.
    const ready = await wrapper
      .evaluate(
        (el) =>
          new Promise<boolean>((resolve) => {
            if (el.getAttribute('data-lexical-initialized') === 'true') return resolve(true)
            const timer = setTimeout(() => {
              observer.disconnect()
              resolve(false)
            }, 15_000)
            const observer = new MutationObserver(() => {
              if (el.getAttribute('data-lexical-initialized') === 'true') {
                clearTimeout(timer)
                observer.disconnect()
                resolve(true)
              }
            })
            observer.observe(el, { attributes: true, attributeFilter: ['data-lexical-initialized'] })
          })
      )
      .catch(() => false)
    test.skip(!ready, 'Lexical loads from esm.sh — the CDN did not answer from this runner')

    const typed = `Hello Lexical ${Date.now()}`
    await wrapper.locator('.lexical-content-editable').click()
    await page.keyboard.type(typed)

    // `registerUpdateListener` writes `$generateHtmlFromNodes` into the hidden input on every
    // change, so the text has to show up there — that value is the one the POST carries.
    await expect
      .poll(() => wrapper.locator('input[type="hidden"][name="content"]').inputValue(), {
        message: 'the hidden input never picked up the typed text',
        timeout: 10_000,
      })
      .toContain(typed)
  })
})
