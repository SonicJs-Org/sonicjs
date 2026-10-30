import { test, expect, Page } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * E2E Test: Field Type Editor Options
 *
 * The collection field modal's type dropdown offers an editor option only while the
 * corresponding editor plugin is active (see `admin-collections-form.template.ts`):
 *   tinymce-plugin -> <option value="richtext">Rich Text (TinyMCE)</option>
 *   quill-editor   -> <option value="quill">Rich Text (Quill)</option>
 *   easy-mdx       -> <option value="markdown">Markdown</option>
 * Everything else in the dropdown is built in and always offered.
 *
 * These tests read the live plugin state from /admin/plugins and assert the dropdown
 * matches it exactly, in both directions. They never install/activate/deactivate anything:
 * the old version toggled tinymce-plugin mid-run, which mutated state shared with every
 * other spec hitting the same server.
 */

const EDITOR_OPTIONS = [
  { plugin: 'TinyMCE Rich Text Editor', value: 'richtext', label: 'Rich Text (TinyMCE)' },
  { plugin: 'Quill Rich Text Editor', value: 'quill', label: 'Rich Text (Quill)' },
  { plugin: 'EasyMDE Markdown Editor', value: 'markdown', label: 'Markdown' },
]

// Built-in field types, offered no matter which plugins are installed.
const BUILTIN_OPTIONS = [
  { value: 'text', label: 'Text' },
  { value: 'slug', label: 'URL Slug' },
  { value: 'number', label: 'Number' },
  { value: 'boolean', label: 'Boolean' },
  { value: 'date', label: 'Date' },
  { value: 'radio', label: 'Radio' },
  { value: 'select', label: 'Select' },
  { value: 'media', label: 'Media' },
  { value: 'reference', label: 'Reference' },
]

async function readPluginStatuses(page: Page): Promise<Map<string, string>> {
  await page.goto('/admin/plugins', { waitUntil: 'domcontentloaded' })
  await page.waitForSelector('.plugin-card', { timeout: 15000 })

  const entries = await page.locator('.plugin-card').evaluateAll((cards) =>
    cards.map((c) => [c.getAttribute('data-name') || '', c.getAttribute('data-status') || ''])
  )
  const statuses = new Map(entries as [string, string][])

  // Every editor plugin must at least be registered, otherwise the assertions below are void
  for (const editor of EDITOR_OPTIONS) {
    expect(statuses.has(editor.plugin), `${editor.plugin} listed on /admin/plugins`).toBe(true)
  }
  return statuses
}

/**
 * Open the Add Field modal on a real collection page.
 * `/admin/collections/new` is now a documentation page with no form, so the modal lives on
 * `/admin/collections/<slug>`. Managed collections render the modal markup but no button
 * wired to `showAddFieldModal()`, so the page's own opener is invoked directly.
 */
async function openFieldTypeDropdown(page: Page) {
  await page.goto('/admin/collections/blog_post', { waitUntil: 'domcontentloaded' })
  await expect(page.locator('h1')).toContainText('Edit Collection')

  await page.waitForFunction(() => typeof (window as any).showAddFieldModal === 'function')
  await page.evaluate(() => (window as any).showAddFieldModal())

  await page.waitForSelector('#field-modal:not(.hidden)', { timeout: 10000 })
  await page.waitForSelector('select#field-type', { state: 'visible', timeout: 10000 })
}

test.describe('Field Type Editor Options @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('should show all active editor options in field type dropdown', async ({ page }) => {
    const statuses = await readPluginStatuses(page)

    await openFieldTypeDropdown(page)

    const fieldTypeOptions = await page.locator('select#field-type option').allTextContents()

    // Built-in types are always present
    for (const builtin of BUILTIN_OPTIONS) {
      expect(fieldTypeOptions).toContain(builtin.label)
    }

    // An editor option must be offered exactly when its plugin is active
    for (const editor of EDITOR_OPTIONS) {
      const isActive = statuses.get(editor.plugin) === 'active'
      expect(
        fieldTypeOptions.includes(editor.label),
        `"${editor.label}" offered while ${editor.plugin} is ${statuses.get(editor.plugin)}`
      ).toBe(isActive)
      await expect(page.locator(`select#field-type option[value="${editor.value}"]`)).toHaveCount(
        isActive ? 1 : 0
      )
    }
  })

  test('should not show inactive editor options', async ({ page }) => {
    const statuses = await readPluginStatuses(page)

    await openFieldTypeDropdown(page)

    const fieldTypeOptions = await page.locator('select#field-type option').allTextContents()

    // Sanity: the dropdown really is populated, so a missing editor option means "filtered
    // out", not "nothing rendered".
    expect(fieldTypeOptions).toContain('Text')

    for (const editor of EDITOR_OPTIONS) {
      if (statuses.get(editor.plugin) === 'active') continue
      expect(fieldTypeOptions).not.toContain(editor.label)
      await expect(page.locator(`select#field-type option[value="${editor.value}"]`)).toHaveCount(0)
    }
  })

  test('should be able to select each editor type', async ({ page }) => {
    const statuses = await readPluginStatuses(page)

    await openFieldTypeDropdown(page)

    const select = page.locator('select#field-type')

    // Every editor whose plugin is active must be selectable
    for (const editor of EDITOR_OPTIONS) {
      if (statuses.get(editor.plugin) !== 'active') continue
      await page.selectOption('select#field-type', editor.value)
      expect(await select.inputValue()).toBe(editor.value)
    }

    // Built-in types must always be selectable
    for (const builtin of BUILTIN_OPTIONS) {
      await page.selectOption('select#field-type', builtin.value)
      expect(await select.inputValue()).toBe(builtin.value)
    }
  })
})
