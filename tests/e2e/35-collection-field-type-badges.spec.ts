import { test, expect, Page } from './fixtures';
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers';

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
