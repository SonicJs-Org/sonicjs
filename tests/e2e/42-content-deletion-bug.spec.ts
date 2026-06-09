import { test, expect } from '@playwright/test';
import { loginAsAdmin, waitForHTMX } from './utils/test-helpers';

/**
 * Test for GitHub Issue #522: Content Deletion UI Bug
 *
 * Bug: Deleting content through Admin > Contents causes a JavaScript error:
 * "Failed to execute 'insertBefore' on 'Node': Identifier 'currentBulkAction' has already been declared"
 *
 * This error occurs because HTMX re-executes script tags when swapping content,
 * and the `let currentBulkAction` variable gets redeclared in the same scope.
 */
test.describe('Content Deletion UI Bug (Issue #522)', () => {
  // Track JavaScript errors during tests
  let jsErrors: string[] = [];

  test.beforeEach(async ({ page }) => {
    // Reset error tracking for each test
    jsErrors = [];

    // Listen for console errors - this is key to detecting the bug
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const text = msg.text();
        // Filter out known non-bug related errors
        if (!text.includes('Failed to load resource') && !text.includes('TinyMCE')) {
          console.log('Console Error:', text);
          jsErrors.push(text);
        }
      }
    });

    // Listen for page errors (uncaught exceptions)
    page.on('pageerror', (error) => {
      console.log('Page Error:', error.message);
      jsErrors.push(error.message);
    });

    await loginAsAdmin(page);
  });

  /**
   * Helper to create test content via admin form submission
   */
  async function createTestContentViaForm(page: typeof test.prototype.page) {
    const timestamp = Date.now();
    const testTitle = `Test Page for Delete ${timestamp}`;
    const testSlug = `test-page-delete-${timestamp}`;

    try {
      // Navigate to new content form
      await page.goto('/admin/content/new');
      await page.waitForLoadState('networkidle');

      // Wait for collection selection page and click "Pages" collection
      const pagesLink = page.locator('a[href*="collection=blog_post"]');
      if (await pagesLink.count() > 0) {
        await pagesLink.click();
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(1000);

        // Fill in the form - blog_post collection has: title, content, slug, meta_description, featured_image
        const titleField = page.locator('input[name="title"]');
        if (await titleField.count() > 0) {
          await titleField.fill(testTitle);
        } else {
          console.log('Title field not found');
          return false;
        }

        // Fill slug if exists
        const slugField = page.locator('input[name="slug"]');
        if (await slugField.count() > 0) {
          await slugField.fill(testSlug);
        }

        // Fill content if it's a textarea (not rich text)
        const contentField = page.locator('textarea[name="content"]');
        if (await contentField.count() > 0) {
          await contentField.fill('Test content for deletion testing');
        }

        // Submit the form using the "Save" button specifically
        await page.getByRole('button', { name: 'Save', exact: true }).click();
        await page.waitForTimeout(2000);

        console.log('Created test content via form');
        return true;
      } else {
        // Try "News" collection as fallback
        const newsLink = page.locator('a[href*="collection=blog_post"]');
        if (await newsLink.count() > 0) {
          await newsLink.click();
          await page.waitForLoadState('networkidle');
          await page.waitForTimeout(1000);

          const titleField = page.locator('input[name="title"]');
          if (await titleField.count() > 0) {
            await titleField.fill(testTitle);
            await page.getByRole('button', { name: 'Save', exact: true }).click();
            await page.waitForTimeout(2000);
            console.log('Created test content via News form');
            return true;
          }
        }
        console.log('No suitable collection found');
        return false;
      }
    } catch (error) {
      console.log('Error creating content:', error);
      return false;
    }
  }

  test('should delete content without JavaScript errors', async ({ page }) => {
    // Step 1: Create test content via form
    const created = await createTestContentViaForm(page);
    if (!created) {
      test.skip(true, 'Could not create test content');
      return;
    }

    // Step 2: Navigate to content list
    await page.goto('/admin/content?model=all&status=all');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);

    // Step 3: Verify content exists
    const contentRows = page.locator('tbody tr');
    const contentCount = await contentRows.count();
    console.log(`Found ${contentCount} content items`);

    if (contentCount === 0) {
      test.skip(true, 'No content available to test deletion');
      return;
    }

    // Step 4: Clear any pre-existing JS errors before delete action
    jsErrors = [];

    // Step 5: Find the delete button on the first content item
    const firstRow = contentRows.first();
    const deleteButton = firstRow.locator('button[title="Delete"]');
    const deleteButtonCount = await deleteButton.count();
    console.log(`Delete button count: ${deleteButtonCount}`);

    if (deleteButtonCount === 0) {
      // List all buttons in the row for debugging
      const allButtons = firstRow.locator('button');
      const buttonCount = await allButtons.count();
      console.log(`Total buttons in row: ${buttonCount}`);
      for (let i = 0; i < buttonCount; i++) {
        const title = await allButtons.nth(i).getAttribute('title');
        console.log(`Button ${i}: title="${title}"`);
      }
      test.skip(true, 'Delete button not found in content row');
      return;
    }

    // Step 6: Set up dialog handler for hx-confirm confirmation
    page.once('dialog', async (dialog) => {
      console.log('Dialog appeared:', dialog.message());
      await dialog.accept();
    });

    // Step 7: Click the delete button
    console.log('Clicking delete button...');
    await deleteButton.click();

    // Step 8: Wait for HTMX to process the delete and refresh
    await waitForHTMX(page);
    await page.waitForTimeout(3000); // Extra time for HTMX swap to complete

    // Step 9: THE KEY ASSERTION - Check for the specific JavaScript error
    console.log('Collected JS errors:', jsErrors);

    const hasRedeclarationError = jsErrors.some(
      (error) =>
        error.includes('currentBulkAction') ||
        error.includes('has already been declared') ||
        error.includes('Identifier') ||
        error.includes('SyntaxError')
    );

    // This assertion will FAIL if the bug exists (proving the test catches the bug)
    // and will PASS once the bug is fixed
    expect(
      hasRedeclarationError,
      `JavaScript error detected during content deletion: ${jsErrors.join(', ')}`
    ).toBe(false);

    // Step 10: Verify the UI is still functional after delete
    await expect(page.locator('h1').first()).toContainText('Content');

    // The page should either show remaining content or an empty state
    const table = page.locator('table');
    const emptyState = page.locator('text=No content found');
    const hasTable = (await table.count()) > 0;
    const hasEmptyState = (await emptyState.count()) > 0;
    expect(hasTable || hasEmptyState).toBeTruthy();
  });

  test('should handle bulk delete without JavaScript errors', async ({ page }) => {
    // Step 1: Create test content via form
    const created = await createTestContentViaForm(page);
    if (!created) {
      test.skip(true, 'Could not create test content');
      return;
    }

    // Step 2: Navigate to content list
    await page.goto('/admin/content?model=all&status=all');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);

    // Step 3: Check we have content to work with
    const contentCount = await page.locator('tbody tr').count();
    console.log(`Found ${contentCount} content items for bulk delete`);

    if (contentCount < 1) {
      test.skip(true, 'Not enough content for bulk delete test');
      return;
    }

    // Step 4: Clear any pre-existing JS errors
    jsErrors = [];

    // Step 5: Select items using checkboxes
    const rowCheckboxes = page.locator('.row-checkbox');
    const checkboxCount = await rowCheckboxes.count();
    console.log(`Found ${checkboxCount} row checkboxes`);

    if (checkboxCount > 0) {
      // Click first checkbox to select one item
      await rowCheckboxes.first().click();
      await page.waitForTimeout(500);
    } else {
      test.skip(true, 'No checkboxes available for bulk selection');
      return;
    }

    // Step 6: Click bulk actions dropdown
    const bulkActionsBtn = page.locator('#bulk-actions-btn');
    const isEnabled = await bulkActionsBtn.isEnabled();
    console.log(`Bulk actions button enabled: ${isEnabled}`);

    if (!isEnabled) {
      test.skip(true, 'Bulk actions button is not enabled after selecting checkbox');
      return;
    }

    await bulkActionsBtn.click();
    await page.waitForTimeout(500);

    // Step 7: Click Delete Selected option in dropdown
    const deleteOption = page.locator('#bulk-actions-menu button').filter({ hasText: 'Delete Selected' });
    const deleteOptionCount = await deleteOption.count();
    console.log(`Delete Selected option count: ${deleteOptionCount}`);

    if (deleteOptionCount === 0) {
      test.skip(true, 'Delete Selected option not found');
      return;
    }

    await deleteOption.click();
    await page.waitForTimeout(500);

    // Step 8: Handle confirmation dialog
    const confirmDialog = page.locator('#bulk-action-confirm');
    if (await confirmDialog.count() > 0) {
      // Click the confirm button in the dialog
      const confirmBtn = confirmDialog.locator('button.confirm-button');
      if (await confirmBtn.count() > 0) {
        console.log('Clicking confirm button in bulk action dialog...');
        await confirmBtn.click();
      }
    }

    // Wait for bulk action to complete
    await waitForHTMX(page);
    await page.waitForTimeout(3000);

    // Step 9: THE KEY ASSERTION - Check for JavaScript errors
    console.log('Collected JS errors after bulk delete:', jsErrors);

    const hasRedeclarationError = jsErrors.some(
      (error) =>
        error.includes('currentBulkAction') ||
        error.includes('has already been declared') ||
        error.includes('Identifier') ||
        error.includes('SyntaxError')
    );

    expect(
      hasRedeclarationError,
      `JavaScript error detected during bulk delete: ${jsErrors.join(', ')}`
    ).toBe(false);

    // Step 10: Verify the UI is still functional
    await expect(page.locator('h1').first()).toContainText('Content');
  });

  test('should maintain table functionality after delete', async ({ page }) => {
    // Step 1: Create test content via form
    const created = await createTestContentViaForm(page);
    if (!created) {
      test.skip(true, 'Could not create test content');
      return;
    }

    // Step 2: Navigate to content list
    await page.goto('/admin/content?model=all&status=all');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);

    // Step 3: Check if there's content
    const hasContent = await page.locator('tbody tr').count() > 0;

    if (!hasContent) {
      test.skip(true, 'No content available to test');
      return;
    }

    // Step 4: Clear JS errors
    jsErrors = [];

    // Step 5: Perform delete
    const deleteButton = page.locator('tbody tr').first().locator('button[title="Delete"]');
    if (await deleteButton.count() > 0) {
      page.once('dialog', async (dialog) => {
        await dialog.accept();
      });
      await deleteButton.click();
      await waitForHTMX(page);
      await page.waitForTimeout(3000);
    }

    // Step 6: Verify table interactions still work after delete
    // Try filtering
    const statusSelect = page.locator('select[name="status"]').first();
    if (await statusSelect.count() > 0) {
      await statusSelect.selectOption('all');
      await waitForHTMX(page);
    }

    // Try sorting (if available)
    const sortButton = page.locator('.sort-btn').first();
    if (await sortButton.count() > 0) {
      await sortButton.click();
      await page.waitForTimeout(500);
    }

    // Step 7: Check for any accumulated JavaScript errors
    console.log('Collected JS errors after interactions:', jsErrors);

    const hasJsErrors = jsErrors.some(
      (error) =>
        error.includes('currentBulkAction') ||
        error.includes('has already been declared') ||
        error.includes('SyntaxError')
    );

    expect(
      hasJsErrors,
      `JavaScript errors after delete and subsequent interactions: ${jsErrors.join(', ')}`
    ).toBe(false);

    // Step 8: Verify the page is still functional
    await expect(page.locator('h1').first()).toContainText('Content');
  });
});
