import { test, expect, Page } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * E2E Test: Field Properties Persistence
 *
 * Collections are code-only now (in-memory `CollectionRegistry`, no `collections` table), so
 * `/admin/collections/<slug>` renders the field list read-only and there is no field PUT
 * endpoint to drive. The two properties this spec has always guarded are still checkable:
 *
 *  1. the field properties the page shows (label, type, required) are the persisted ones and
 *     survive a reload unchanged;
 *  2. the field form submits all three critical properties — `field_type`, `is_required` and
 *     `is_searchable` — including when the checkboxes are unchecked (the hidden-input pair),
 *     which is exactly what the old "PUT request data" assertion was protecting.
 *
 * `news-collection` no longer exists; `e2e_test` is the richest current collection.
 */

const COLLECTION = 'e2e_test'

type FieldRow = { label: string; name: string; type: string; required: boolean }

async function readFieldRows(page: Page): Promise<FieldRow[]> {
  await expect(page.locator('h1')).toContainText('Edit Collection')
  await page.waitForSelector('code.font-mono', { timeout: 15000 })

  return page
    .locator('div.bg-zinc-50.rounded-lg.border.p-4')
    .filter({ has: page.locator('code.font-mono') })
    .evaluateAll((rows) =>
      rows.map((row) => {
        const badges = Array.from(row.querySelectorAll('span.inline-flex.items-center.rounded-md'))
          .map((b) => (b.textContent || '').replace(/\s+/g, ' ').trim())
        return {
          label: (row.querySelector('span.font-medium')?.textContent || '').trim(),
          name: (row.querySelector('code.font-mono')?.textContent || '').trim(),
          type: badges[0] || '',
          required: badges.includes('Required'),
        }
      })
    )
}

/**
 * Managed collections render the Add/Edit Field modal markup but no button wired to
 * `showAddFieldModal()`, so the page's own opener is invoked directly.
 */
async function openFieldModal(page: Page) {
  await page.waitForFunction(() => typeof (window as any).showAddFieldModal === 'function')
  await page.evaluate(() => (window as any).showAddFieldModal())
  await page.waitForSelector('#field-modal:not(.hidden)', { timeout: 10000 })
  await page.waitForSelector('#field-type', { state: 'visible', timeout: 10000 })
}

/** Last value submitted for each form key (hidden/checkbox pairs submit the key twice). */
async function fieldFormPayload(page: Page): Promise<Record<string, string>> {
  return page.evaluate(() => {
    const form = document.getElementById('field-form') as HTMLFormElement
    const out: Record<string, string> = {}
    // Hidden/checkbox pairs submit the same key twice; the last value is the effective one.
    new FormData(form).forEach((value, key) => {
      out[key] = String(value)
    })
    return out
  })
}

test.describe('Field Properties Persistence @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('should persist all field properties when editing a field', async ({ page }) => {
    await page.goto(`/admin/collections/${COLLECTION}`, { waitUntil: 'domcontentloaded' })

    const before = await readFieldRows(page)
    expect(before.length).toBeGreaterThan(0)

    // Every field must expose a name, a type and a required flag
    for (const field of before) {
      expect(field.name, 'field name rendered').not.toBe('')
      expect(field.label, `label for ${field.name}`).not.toBe('')
      expect(field.type, `type badge for ${field.name}`).not.toBe('')
    }

    // Spot-check the persisted values against the collection definition in code
    const byName = new Map(before.map((f) => [f.name, f]))
    expect(byName.get('slug')).toMatchObject({ label: 'URL Slug', type: 'URL Slug', required: true })
    expect(byName.get('count')).toMatchObject({ type: 'Number', required: false })
    expect(byName.get('isActive')).toMatchObject({ type: 'Boolean', required: false })
    expect(byName.get('publishDate')).toMatchObject({ type: 'Date', required: false })
    expect(byName.get('featuredImage')).toMatchObject({ type: 'Media', required: false })

    // Reload and confirm nothing drifts
    await page.reload({ waitUntil: 'domcontentloaded' })
    const after = await readFieldRows(page)
    expect(after).toEqual(before)
  })

  test('should show all field properties in PUT request data', async ({ page }) => {
    await page.goto(`/admin/collections/${COLLECTION}`, { waitUntil: 'domcontentloaded' })
    await openFieldModal(page)

    // All three critical properties must be part of the submitted payload, not just the UI
    const initial = await fieldFormPayload(page)
    expect(Object.keys(initial)).toContain('field_type')
    expect(Object.keys(initial)).toContain('is_required')
    expect(Object.keys(initial)).toContain('is_searchable')

    await page.selectOption('#field-type', 'text')
    await page.locator('#field-required').check()
    await page.locator('#field-searchable').check()

    const checked = await fieldFormPayload(page)
    expect(checked.field_type).toBe('text')
    expect(checked.is_required).toBe('1')
    expect(checked.is_searchable).toBe('1')

    // Unchecking must still submit the properties (hidden "0" companions), otherwise the
    // server cannot tell "turned off" from "not sent".
    await page.locator('#field-required').uncheck()
    await page.locator('#field-searchable').uncheck()

    const unchecked = await fieldFormPayload(page)
    expect(unchecked.field_type).toBe('text')
    expect(unchecked.is_required).toBe('0')
    expect(unchecked.is_searchable).toBe('0')
  })
})
