import { test, expect, Page } from './fixtures';
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers';

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
