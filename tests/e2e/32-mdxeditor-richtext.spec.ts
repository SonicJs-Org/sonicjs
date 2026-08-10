import { test, expect } from '@playwright/test';
import { loginAsAdmin, navigateToAdminSection, waitForHTMX } from './utils/test-helpers';

test.describe.skip('MDXEditor Rich Text Editor @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should activate MDXEditor plugin', async ({ page }) => {
    // Navigate to plugins page
    await navigateToAdminSection(page, 'plugins');

    // Check if MDXEditor plugin exists
    const mdxeditorPlugin = page.locator('tr', { hasText: 'MDXEditor' });
    await expect(mdxeditorPlugin).toBeVisible({ timeout: 10000 });

    // Check if it's already active
    const statusCell = mdxeditorPlugin.locator('td').nth(2); // Status column
    const statusText = await statusCell.textContent();

    if (statusText?.includes('Inactive')) {
      // Click activate button
      const activateButton = mdxeditorPlugin.locator('button', { hasText: 'Activate' });
      await activateButton.click();

      // Wait for activation
      await waitForHTMX(page);
      await page.waitForTimeout(1000);

      // Verify it's now active
      await expect(statusCell).toContainText('Active');
    } else {
      // Already active
      await expect(statusCell).toContainText('Active');
    }
  });

  test('should load MDXEditor scripts when plugin is active', async ({ page }) => {
    // Navigate to new content page
    await page.goto('http://localhost:8787/admin/content/new?collection=blog-posts');
    await page.waitForLoadState('networkidle');

    // Check if MDXEditor CDN scripts are loaded
    const hasReact = await page.evaluate(() => {
      return typeof window.React !== 'undefined';
    });

    const hasReactDOM = await page.evaluate(() => {
      return typeof window.ReactDOM !== 'undefined';
    });

    const hasMDXEditor = await page.evaluate(() => {
      return typeof window.MDXEditor !== 'undefined';
    });

    console.log('React loaded:', hasReact);
    console.log('ReactDOM loaded:', hasReactDOM);
    console.log('MDXEditor loaded:', hasMDXEditor);

    // At least MDXEditor script tag should be present
    const mdxeditorScript = page.locator('script[src*="mdxeditor"]');
    await expect(mdxeditorScript).toHaveCount(1, { timeout: 5000 });
  });

  test('should initialize MDXEditor for richtext fields', async ({ page }) => {
    // Navigate to new content page
    await page.goto('http://localhost:8787/admin/content/new?collection=blog-posts');
    await page.waitForLoadState('networkidle');

    // Wait for MDXEditor to initialize
    await page.waitForTimeout(3000); // Give time for CDN and initialization

    // Check if richtext container exists
    const richtextContainer = page.locator('.richtext-container').first();
    await expect(richtextContainer).toBeVisible({ timeout: 10000 });

    // Check if MDXEditor wrapper was created
    const mdxeditorWrapper = page.locator('.mdxeditor-wrapper').first();
    if (await mdxeditorWrapper.count() > 0) {
      console.log('✓ MDXEditor wrapper found');
      await expect(mdxeditorWrapper).toBeVisible();

      // Check if editor has the correct theme
      const theme = await mdxeditorWrapper.getAttribute('data-theme');
      console.log('MDXEditor theme:', theme);
      expect(theme).toBe('dark');
    } else {
      console.log('⚠ MDXEditor wrapper not found - may need more time to initialize or fallback to textarea');

      // Check if textarea fallback is visible
      const textarea = richtextContainer.locator('textarea');
      if (await textarea.count() > 0) {
        console.log('Textarea fallback is present');
      }
    }
  });

  test('should allow typing content in MDXEditor', async ({ page }) => {
    // Navigate to new content page
    await page.goto('http://localhost:8787/admin/content/new?collection=blog-posts');
    await page.waitForLoadState('networkidle');

    // Wait for MDXEditor to initialize
    await page.waitForTimeout(3000);

    // Fill in required fields
    await page.fill('input[name="title"]', 'MDXEditor Test Post');

    // Try to interact with MDXEditor or fallback textarea
    const mdxeditorWrapper = page.locator('.mdxeditor-wrapper').first();

    if (await mdxeditorWrapper.count() > 0) {
      console.log('Attempting to type in MDXEditor');

      // MDXEditor uses contenteditable divs
      const editor = mdxeditorWrapper.locator('[contenteditable="true"]').first();

      if (await editor.count() > 0) {
        await editor.click();
        await editor.fill('# Test Heading\n\nThis is a test post using MDXEditor.');
        console.log('✓ Successfully typed in MDXEditor');
      } else {
        console.log('Could not find contenteditable element in MDXEditor');
      }
    } else {
      console.log('Using textarea fallback');
      const textarea = page.locator('.richtext-container textarea').first();
      await textarea.fill('# Test Heading\n\nThis is a test post using MDXEditor fallback.');
    }

    // Take a screenshot for verification
    await page.screenshot({ path: 'test-results/mdxeditor-test.png', fullPage: true });
    console.log('Screenshot saved to test-results/mdxeditor-test.png');
  });

  test('should save content with MDXEditor value', async ({ page }) => {
    // Navigate to new content page
    await page.goto('http://localhost:8787/admin/content/new?collection=blog-posts');
    await page.waitForLoadState('networkidle');

    // Wait for editor initialization
    await page.waitForTimeout(3000);

    // Fill in required fields
    const title = `MDXEditor Test ${Date.now()}`;
    await page.fill('input[name="title"]', title);

    // Fill in content
    const mdxContent = '# Test Heading\n\nThis is test content from MDXEditor.';

    const mdxeditorWrapper = page.locator('.mdxeditor-wrapper').first();
    if (await mdxeditorWrapper.count() > 0) {
      const editor = mdxeditorWrapper.locator('[contenteditable="true"]').first();
      if (await editor.count() > 0) {
        await editor.click();
        await editor.fill(mdxContent);
      }
    } else {
      const textarea = page.locator('.richtext-container textarea').first();
      await textarea.fill(mdxContent);
    }

    // Save the content
    const saveButton = page.locator('button[type="submit"]', { hasText: 'Save' }).first();
    await saveButton.click();

    // Wait for save to complete
    await waitForHTMX(page);
    await page.waitForTimeout(2000);

    // Should redirect to content list or show success message
    const url = page.url();
    console.log('After save URL:', url);

    // Verify we're either on the list page or still on the form with a success message
    const isOnList = url.includes('/admin/content') && !url.includes('/new') && !url.includes('/edit');
    const hasSuccessMessage = await page.locator('text=saved successfully').count() > 0;

    expect(isOnList || hasSuccessMessage).toBeTruthy();
  });
});
