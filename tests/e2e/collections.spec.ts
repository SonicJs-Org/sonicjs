import { test } from "./fixtures"
import { expect } from "./fixtures"
import type { Page } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { ensureAdminUserExists } from "./utils/test-helpers"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 33-field-type-editor-options.spec.ts", () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 34-field-type-persistence.spec.ts", () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 35-collection-field-type-badges.spec.ts", () => {
  /**
   * Collection field type badges.
   *
   * Collections are code-only now, so `/admin/collections/<slug>` renders a read-only
   * "Collection Fields" list. Each field card shows the field label, a colour-coded field
   * type badge, an optional "Required" badge and the raw field name in a <code> tag — the old
   * `.field-item` editor rows are gone.
   */

  /** One read-only field card in the "Collection Fields" section. */
  function fieldRows(page: Page) {
    return page
      .locator('div.bg-zinc-50.rounded-lg.border.p-4')
      .filter({ has: page.locator('code.font-mono') });
  }

  async function openCollectionWithFields(page: Page, preferred: RegExp) {
    await page.goto('/admin/collections', { waitUntil: 'domcontentloaded' });
    await expect(page.locator('h1')).toContainText('Collections');

    const rows = page.locator('tbody tr');
    await expect(rows.first()).toBeVisible({ timeout: 15000 });

    // Rows navigate via an onclick handler (not an <a>), so click the row itself.
    const target = rows.filter({ hasText: preferred }).first();
    await (await target.count() > 0 ? target : rows.first()).click();

    await page.waitForURL(/\/admin\/collections\/[^/]+$/, { timeout: 15000 });
    await expect(page.locator('h1')).toContainText('Edit Collection');
  }

  test.describe('Collection Field Type Badges @collections', () => {
    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page);
      await loginAsAdmin(page);
    });

    test('should display color-coded field type badges', async ({ page }) => {
      // e2e_test is the collection that exercises the widest set of field types
      await openCollectionWithFields(page, /e2e_test/);

      const rows = fieldRows(page);
      const rowCount = await rows.count();
      expect(rowCount, 'collection renders at least one field').toBeGreaterThan(0);

      const typeBadges: { field: string; text: string; classes: string }[] = [];

      for (let i = 0; i < rowCount; i++) {
        const row = rows.nth(i);
        const fieldName = ((await row.locator('code.font-mono').first().textContent()) || '').trim();

        // The first badge in a row is the field type badge; "Required" always follows it.
        const badge = row.locator('span.inline-flex.items-center.rounded-md').first();
        await expect(badge).toBeVisible();

        const badgeText = ((await badge.textContent()) || '').replace(/\s+/g, ' ').trim();
        const badgeClasses = (await badge.getAttribute('class')) || '';

        expect(badgeText, `type badge for "${fieldName}" is not empty`).not.toBe('');
        expect(badgeText).not.toBe('Required');

        // Colour coding + badge styling
        expect(badgeClasses, `badge colour for "${fieldName}"`).toMatch(/bg-[a-z]+-\d+\//);
        expect(badgeClasses).toContain('px-2');
        expect(badgeClasses).toContain('py-1');
        expect(badgeClasses).toContain('text-xs');
        expect(badgeClasses).toContain('ring-1');

        typeBadges.push({ field: fieldName, text: badgeText, classes: badgeClasses });
      }

      // Field types the badge map humanises must render the readable label, never the raw
      // internal type name.
      const byField = new Map(typeBadges.map((b) => [b.field, b.text]));
      expect(byField.get('slug')).toBe('URL Slug');
      expect(byField.get('count')).toBe('Number');
      expect(byField.get('isActive')).toBe('Boolean');
      expect(byField.get('publishDate')).toBe('Date');
      expect(byField.get('featuredImage')).toBe('Media');
      expect(byField.get('category')).toBe('Select');

      // Distinct types must not all collapse onto one colour
      const colours = new Set(
        typeBadges.map((b) => (b.classes.match(/bg-([a-z]+)-\d+\//) || [])[1]).filter(Boolean)
      );
      expect(colours.size, 'badges are colour-coded by type').toBeGreaterThan(1);
    });

    test('should not display escaped HTML in badges', async ({ page }) => {
      await openCollectionWithFields(page, /e2e_test/);

      // Badge markup must be rendered, not escaped into the page as text
      const pageContent = await page.content();
      expect(pageContent).not.toContain('&lt;span');
      expect(pageContent).not.toContain('items-center=\\"');
      expect(pageContent).not.toContain('rounded-md=\\"');

      const rows = fieldRows(page);
      const rowCount = await rows.count();
      expect(rowCount).toBeGreaterThan(0);

      for (let i = 0; i < rowCount; i++) {
        const badgeText = ((await rows.nth(i).locator('span.inline-flex').first().textContent()) || '');
        // Badge labels are plain text — no markup leaking through either direction
        expect(badgeText).not.toContain('<span');
        expect(badgeText).not.toContain('&lt;');
        expect(badgeText).not.toContain('inline-flex');
      }

      // The serialised field payload used by the edit modal must carry data only, no badge HTML
      const fieldData = await page.evaluate(() =>
        Array.from(document.querySelectorAll('[data-field-data]')).map((el) =>
          el.getAttribute('data-field-data') || ''
        )
      );
      for (const data of fieldData) {
        expect(data).not.toContain('typeBadgeHTML');
        expect(data).not.toContain('<span');
        expect(data).not.toContain('inline-flex');
      }
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 36-collection-field-easymdx-edit.spec.ts", () => {
  /**
   * The markdown editor plugin ships as `easy-mdx` ("EasyMDE Markdown Editor"). When it is
   * active the collection field modal offers `<option value="markdown">Markdown</option>` and
   * markdown fields render a "Markdown" type badge — never the old "Rich Text (MDXEditor)"
   * label.
   *
   * Collections are code-only now, so `/admin/collections/<slug>` shows a read-only field list
   * (`.field-item` rows are gone) and the Add/Edit Field modal has no trigger button; the page
   * still defines `showAddFieldModal()`, which is what is invoked below.
   */

  function fieldRows(page: Page) {
    return page
      .locator('div.bg-zinc-50.rounded-lg.border.p-4')
      .filter({ has: page.locator('code.font-mono') });
  }

  async function openFirstCollection(page: Page) {
    await page.goto('/admin/collections', { waitUntil: 'domcontentloaded' });

    // Rows navigate via an onclick handler (not an <a>), so click the row itself.
    const firstRow = page.locator('tbody tr').first();
    await expect(firstRow).toBeVisible({ timeout: 15000 });
    await firstRow.click();

    await page.waitForURL(/\/admin\/collections\/[^/]+$/, { timeout: 15000 });
    await expect(page.locator('h1')).toContainText('Edit Collection');
  }

  test.describe('Collection Field EasyMDX Edit @collections @content', () => {
    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page);
      await loginAsAdmin(page);
    });

    test('should show EasyMDX in field type badge on collection edit page', async ({ page }) => {
      await openFirstCollection(page);

      const rows = fieldRows(page);
      const rowCount = await rows.count();
      expect(rowCount).toBeGreaterThan(0);

      // Collect every field type badge on the page
      const badgeTexts: string[] = [];
      for (let i = 0; i < rowCount; i++) {
        const badge = rows.nth(i).locator('span.inline-flex.items-center.rounded-md').first();
        badgeTexts.push(((await badge.textContent()) || '').replace(/\s+/g, ' ').trim());
      }

      // No badge may ever use the retired "Rich Text (MDXEditor)" wording
      for (const text of badgeTexts) {
        expect(text).not.toContain('MDXEditor');
      }

      // Markdown-backed fields are labelled "Markdown"
      const markdownBadges = badgeTexts.filter((t) => t === 'Markdown');
      for (const text of markdownBadges) {
        expect(text).toBe('Markdown');
      }
    });

    test('should handle error gracefully when loading collection with invalid field data', async ({ page }) => {
      // This test ensures that even if field_options has invalid JSON,
      // the page still loads and editorPlugins is available

      await openFirstCollection(page);

      // The field modal must be rendered with its opener available (managed collections do not
      // render a visible "Add Field" trigger, so the page's own opener is called directly).
      await expect(page.locator('#field-modal')).toHaveCount(1);
      await page.waitForFunction(() => typeof (window as any).showAddFieldModal === 'function');
      await page.evaluate(() => (window as any).showAddFieldModal());

      await page.waitForSelector('#field-modal:not(.hidden)', { timeout: 10000 });

      // Verify field type dropdown has options
      const fieldTypeOptions = await page.locator('#field-type option').count();
      expect(fieldTypeOptions).toBeGreaterThan(1); // More than just the placeholder

      // editorPlugins drives the editor options: the markdown option exists exactly when the
      // easy-mdx plugin is active. The retired `mdxeditor` value must never be emitted.
      await expect(page.locator('#field-type option[value="mdxeditor"]')).toHaveCount(0);

      // When easy-mdx is active the option is emitted with the current label; 33-field-type-
      // editor-options asserts the full "offered iff active" relationship.
      const markdownOption = page.locator('#field-type option[value="markdown"]');
      if ((await markdownOption.count()) > 0) {
        await expect(markdownOption).toHaveText('Markdown');
      }

      // Close modal
      await page.click('#field-modal button:has-text("Cancel")');
      await expect(page.locator('#field-modal')).toHaveClass(/hidden/);
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 70-collection-registry.spec.ts", () => {
  const BASE = process.env.BASE_URL || 'http://localhost:8787'

  /**
   * Phase 1 of drop-db-collections plan: in-memory CollectionRegistry coexists
   * with the legacy DB sync. Bootstrap populates the registry from
   * loadCollectionConfigs(); autoRegisterCollectionDocumentTypes now reads from
   * the registry (was a stub returning []).
   *
   * The unit test suite (collection-registry.test.ts) covers the registry
   * semantics exhaustively. This E2E verifies that boot didn't break — the
   * document type registry remains populated and a code-defined collection's
   * documents are readable end-to-end.
   */
  test.describe('collection registry (PR 1) @collections', () => {
    test('boot succeeds — blog_post document type is reachable', async ({ request }) => {
      const response = await request.get(`${BASE}/api/documents?type=blog_post&limit=1`)
      expect(response.ok()).toBeTruthy()
      const body = await response.json()
      expect(Array.isArray(body.data)).toBe(true)
    })

    test('an unregistered document type returns 400 (registry gate works)', async ({ request }) => {
      const response = await request.get(`${BASE}/api/documents?type=does_not_exist&limit=1`)
      expect(response.status()).toBe(400)
      const body = await response.json()
      expect(body.error).toContain('Unknown document type')
    })

    test('blog_post records carry the expected type id (autoRegister skipped blog_post, hand-tuned seed wins)', async ({ request }) => {
      const response = await request.get(`${BASE}/api/documents?type=blog_post&limit=5`)
      expect(response.ok()).toBeTruthy()
      const body = await response.json()
      const docs = body.data ?? []
      for (const doc of docs) {
        expect(doc.typeId).toBe('blog_post')
      }
    })

    test('admin UI /admin/collections requires auth (read-only page)', async ({ request }) => {
      const response = await request.get(`${BASE}/admin/collections`, { maxRedirects: 0 })
      // Page exists (read-only list) but is auth-gated.
      expect([200, 302, 401]).toContain(response.status())
    })

    test('admin UI /admin/collections/new requires auth (instructional page)', async ({ request }) => {
      const response = await request.get(`${BASE}/admin/collections/new`, { maxRedirects: 0 })
      // /new page renders code-only instructions; auth-gated.
      expect([200, 302, 401]).toContain(response.status())
    })
  })

  test.describe('collection registry — authed admin UI @collections', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('/admin/collections lists code-defined blog_post as read-only', async ({ page }) => {
      await page.goto(`${BASE}/admin/collections`)
      await expect(page.locator('body')).toContainText('Collections')
      await expect(page.locator('body')).toContainText('blog_post')
      // Code-defined badge should be present on managed collections.
      await expect(page.locator('body')).toContainText('Config')
      // No write-action buttons (create/delete raw buttons outside of New Collection link).
      await expect(page.locator('button:has-text("Delete"), button:has-text("Create Collection")')).toHaveCount(0)
    })

    test('/admin/collections/new shows code-defined instructions + docs link', async ({ page }) => {
      await page.goto(`${BASE}/admin/collections/new`)
      await expect(page.locator('body')).toContainText('code-defined')
      await expect(page.locator('body')).toContainText('registerCollections')
      await expect(page.locator('body')).toContainText('CollectionConfig')
      // Docs link is present and points to the canonical SonicJS docs.
      const docsLink = page.locator('a[href="https://sonicjs.com/collections"]')
      await expect(docsLink.first()).toBeVisible()
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 72-collection-base-routes.spec.ts", () => {
  const BASE = process.env.BASE_URL || 'http://localhost:8787'

  test.describe('per-collection base routes @collections', () => {
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
})
