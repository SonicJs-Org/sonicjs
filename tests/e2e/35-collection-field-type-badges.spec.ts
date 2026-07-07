import { test, expect } from '@playwright/test';
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers';

// Use environment variable for port or default to 8787
const BASE_URL = process.env.BASE_URL || 'http://localhost:8787';

test.describe.skip('Collection Field Type Badges @collections', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page);
    await loginAsAdmin(page);
  });

  test('should display color-coded field type badges', async ({ page }) => {
    // Navigate to collections page
    await page.goto(`${BASE_URL}/admin/collections`);
    await expect(page.locator('h1')).toContainText('Collections');

    // Find and click on a collection that has fields (look for "page" or "blog post")
    const rows = page.locator('tbody tr');
    const rowCount = await rows.count();

    let foundCollection = false;
    for (let i = 0; i < rowCount; i++) {
      const row = rows.nth(i);
      const rowText = await row.textContent();

      // Look for collections that typically have fields
      if (rowText?.toLowerCase().includes('page') ||
          rowText?.toLowerCase().includes('blog') ||
          rowText?.toLowerCase().includes('post')) {
        await row.click();
        foundCollection = true;
        break;
      }
    }

    // If we didn't find a specific collection, just click the first one
    if (!foundCollection) {
      await rows.first().click();
    }

    // Wait for the edit page to load
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1')).toContainText('Edit Collection');

    // Wait a bit for the page to fully render
    await page.waitForTimeout(1000);

    // Check if there are existing fields - try multiple selectors
    let fieldItems = page.locator('.field-item');
    let fieldCount = await fieldItems.count();

    console.log(`Found ${fieldCount} field items with .field-item selector`);

    // If no fields found with .field-item, try looking for the field list container
    if (fieldCount === 0) {
      // Look for any elements that might contain field information
      const fieldLabels = page.locator('span.text-sm\\/6.font-medium');
      fieldCount = await fieldLabels.count();
      console.log(`Found ${fieldCount} field labels`);
    }

    if (fieldCount > 0) {
      // Look for ANY badge with the inline-flex class on the page
      const badges = page.locator('span.inline-flex.items-center.rounded-md');
      const badgeCount = await badges.count();

      console.log(`Found ${badgeCount} total badges on page`);

      // Filter badges to only field type badges (exclude Required, Draft, Searchable, and version badges)
      let fieldTypeBadge = null;
      for (let i = 0; i < badgeCount; i++) {
        const badge = badges.nth(i);
        const badgeText = ((await badge.textContent()) || '').replace(/\s+/g, ' ').trim();

        // Skip "Required", "Draft", "Searchable" badges and version number badges (e.g., "2.0.10")
        if (badgeText.includes('Required') ||
            badgeText.includes('Draft') ||
            badgeText.includes('Searchable') ||
            /^\d+\.\d+/.test(badgeText)) {  // Skip version numbers like "2.0.10"
          console.log(`Skipping badge: "${badgeText}"`);
          continue;
        }

        // This should be a field type badge
        console.log(`Found field type badge: "${badgeText}"`);
        fieldTypeBadge = badge;
        break;
      }

      if (fieldTypeBadge) {
        // Check if badge exists
        await expect(fieldTypeBadge).toBeVisible({ timeout: 5000 });

        // Get the badge text
        const badgeText = await fieldTypeBadge.textContent();
        console.log(`Field type badge text: ${badgeText}`);

        // Badge should not be empty
        expect(badgeText).toBeTruthy();
        expect(badgeText?.trim()).not.toBe('');

        // Badge should have color classes (check for bg- class which indicates styling)
        const badgeClasses = await fieldTypeBadge.getAttribute('class');
        console.log(`Badge classes: ${badgeClasses}`);

        // Should have background color class
        expect(badgeClasses).toMatch(/bg-(blue|purple|green|amber|cyan|indigo|rose|zinc)-\d+/);

        // Should have proper badge styling
        expect(badgeClasses).toContain('px-2');
        expect(badgeClasses).toContain('py-1');
        expect(badgeClasses).toContain('text-xs');
        expect(badgeClasses).toContain('ring-1');

        // Badge text should be a readable label, not raw field type
        // Should NOT be values like "text", "richtext", "string", etc.
        const readableLabels = ['Text', 'Rich Text', 'Number', 'Boolean', 'Date', 'Select', 'Media'];
        const isReadable = readableLabels.some(label => badgeText?.includes(label));
        expect(isReadable).toBeTruthy();

        console.log('✅ Field type badge is displaying correctly with proper styling and readable label');
      } else {
        throw new Error('No field type badges found on page, only Required/Draft badges');
      }
    } else {
      throw new Error('No fields found in any collection - cannot test badges');
    }
  });

  test('should not display escaped HTML in badges', async ({ page }) => {
    // Navigate to collections page
    await page.goto(`${BASE_URL}/admin/collections`);

    // Click on the first collection
    const firstRow = page.locator('tbody tr').first();
    await firstRow.click();

    // Wait for page load
    await page.waitForLoadState('networkidle');

    // Check for escaped HTML in the page content
    const pageContent = await page.content();

    // Should NOT contain escaped HTML like &lt;span or \"
    expect(pageContent).not.toContain('&lt;span');
    expect(pageContent).not.toContain('items-center=\\\"');
    expect(pageContent).not.toContain('rounded-md=\\\"');

    // Check data attributes don't contain typeBadgeHTML
    const fieldItems = page.locator('.field-item');
    if (await fieldItems.count() > 0) {
      const firstField = fieldItems.first();
      const dataFieldData = await firstField.getAttribute('data-field-data');

      if (dataFieldData) {
        // Data attribute should not contain badge HTML
        expect(dataFieldData).not.toContain('typeBadgeHTML');
        expect(dataFieldData).not.toContain('<span');
        expect(dataFieldData).not.toContain('inline-flex');

        console.log('✅ Data attribute is clean without badge HTML');
      }
    }
  });
});
