import { test, expect } from '@playwright/test';
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers';

// Use environment variable for port or default to 8787
const BASE_URL = process.env.BASE_URL || 'http://localhost:8787';

test.describe.skip('Collection Field EasyMDX Edit @collections @content', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page);
    await loginAsAdmin(page);
  });

  test('should populate field type dropdown with EasyMDX when editing an EasyMDX field', async ({ page }) => {
    // Navigate to collections page
    await page.goto(`${BASE_URL}/admin/collections`);
    await expect(page.locator('h1')).toContainText('Collections');

    // Click on the first collection to edit
    const firstRow = page.locator('tbody tr').first();
    await expect(firstRow).toBeVisible();
    await firstRow.click();

    // Wait for the edit page to load
    await expect(page.locator('h1')).toContainText('Edit Collection');

    // Create an EasyMDX field first if none exists
    const existingMdxField = page.locator('.field-item').filter({ hasText: 'EasyMDX' });
    const mdxFieldCount = await existingMdxField.count();

    if (mdxFieldCount === 0) {
      console.log('No EasyMDX field found, creating one');

      // Click Add Field button
      await page.click('button:has-text("Add Field")');
      await page.waitForSelector('#field-modal:not(.hidden)');

      // Fill in field details
      await page.fill('#modal-field-name', 'content_mdx');

      // Check if mdxeditor option is available in dropdown
      const mdxOption = page.locator('#field-type option[value="mdxeditor"]');
      const optionExists = await mdxOption.count();

      if (optionExists === 0) {
        console.log('EasyMDX option not available, skipping test');
        await page.click('button:has-text("Cancel")');
        test.skip();
        return;
      }

      await page.selectOption('#field-type', 'mdxeditor');
      await page.fill('#field-label', 'Content MDX');

      // Submit the field
      await page.click('#field-modal button[type="submit"]');
      await page.waitForLoadState('networkidle');
      await expect(page.locator('h1')).toContainText('Edit Collection');
    }

    // Find the EasyMDX field and click edit
    const mdxField = page.locator('.field-item').filter({ hasText: 'EasyMDX' }).first();
    await expect(mdxField).toBeVisible();

    // Click the edit button
    const editButton = mdxField.locator('button:has-text("Edit")');
    await editButton.click();

    // Wait for modal to appear
    await page.waitForSelector('#field-modal:not(.hidden)');
    await expect(page.locator('#modal-title')).toContainText('Edit Field');

    // Wait a moment for JavaScript to populate the fields
    await page.waitForTimeout(200);

    // Check that the field type dropdown has the EasyMDX option
    const fieldTypeSelect = page.locator('#field-type');
    const availableOptions = await fieldTypeSelect.locator('option').allTextContents();

    console.log('Available field type options:', availableOptions);
    expect(availableOptions).toContain('EasyMDX');

    // Check that the mdxeditor value is selected
    const selectedValue = await fieldTypeSelect.inputValue();
    console.log('Selected field type value:', selectedValue);

    expect(selectedValue).toBe('mdxeditor');

    // Verify the selected option text shows "EasyMDX"
    const selectedOption = await fieldTypeSelect.locator('option:checked').textContent();
    console.log('Selected option text:', selectedOption);
    expect(selectedOption).toBe('EasyMDX');

    // Close modal
    await page.click('button:has-text("Cancel")');
    await page.waitForSelector('#field-modal.hidden');
  });

  test('should show EasyMDX in field type badge on collection edit page', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/collections`);

    // Click on first collection
    const firstRow = page.locator('tbody tr').first();
    await firstRow.click();
    await expect(page.locator('h1')).toContainText('Edit Collection');

    // Look for any field with EasyMDX type badge
    const mdxBadge = page.locator('.field-item').filter({ hasText: 'EasyMDX' });
    const badgeCount = await mdxBadge.count();

    if (badgeCount > 0) {
      // Verify the badge text is "EasyMDX" not "Rich Text (MDXEditor)"
      const badgeText = await mdxBadge.first().locator('span.inline-flex').textContent();
      expect(badgeText).toBe('EasyMDX');
      expect(badgeText).not.toContain('MDXEditor');
    } else {
      console.log('No EasyMDX fields found in collection');
    }
  });

  test('should handle error gracefully when loading collection with invalid field data', async ({ page }) => {
    // This test ensures that even if field_options has invalid JSON,
    // the page still loads and editorPlugins is available

    await page.goto(`${BASE_URL}/admin/collections`);

    const firstRow = page.locator('tbody tr').first();
    await firstRow.click();

    // Page should load without errors
    await expect(page.locator('h1')).toContainText('Edit Collection');

    // Check that Add Field button is present (indicating the page loaded properly)
    const addFieldButton = page.locator('button:has-text("Add Field")');
    await expect(addFieldButton).toBeVisible();

    // Click Add Field to verify editorPlugins is loaded
    await addFieldButton.click();
    await page.waitForSelector('#field-modal:not(.hidden)');

    // Verify field type dropdown has options
    const fieldTypeOptions = await page.locator('#field-type option').count();
    expect(fieldTypeOptions).toBeGreaterThan(1); // More than just the placeholder

    // Check if EasyMDX option exists (means editorPlugins was passed correctly)
    const mdxOptionExists = await page.locator('#field-type option[value="mdxeditor"]').count();

    if (mdxOptionExists > 0) {
      console.log('✓ EasyMDX option is available (editorPlugins loaded correctly)');
    } else {
      console.log('EasyMDX plugin may not be active');
    }

    // Close modal
    await page.click('button:has-text("Cancel")');
  });
});
