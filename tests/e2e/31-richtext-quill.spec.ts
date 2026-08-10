import { test, expect } from '@playwright/test';
import { loginAsAdmin, navigateToAdminSection } from './utils/test-helpers';

test.describe.skip('Rich Text Editor (Quill) @content', () => {
  // Activate plugin before all tests
  test.beforeAll(async ({ request }) => {
    // Install and activate Quill plugin via API
    await request.post('/admin/plugins/quill-editor/install');
    await request.post('/admin/plugins/quill-editor/activate');
    // Wait a bit for activation to complete
    await new Promise(resolve => setTimeout(resolve, 1000));
  });

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should load Quill for blog post content field', async ({ page }) => {
    // Navigate to create new blog post
    await navigateToAdminSection(page, 'content');

    // Click "New Content" link
    await page.click('a[href="/admin/content/new"]');

    // Wait for collection selection page
    await page.waitForURL('/admin/content/new', { timeout: 10000 });
    await expect(page.locator('h1')).toContainText('Create New Content');

    // Click on Blog Posts collection
    await page.click('text=Blog Posts');

    // Wait for the form to load
    await page.waitForSelector('input[name="title"]', { timeout: 10000 });

    // Wait for Quill to initialize
    await page.waitForTimeout(2000);

    // Check for Quill editor container
    const quillContainer = page.locator('.ql-container').first();
    await expect(quillContainer).toBeVisible({ timeout: 5000 });

    // Check for Quill toolbar
    const toolbar = page.locator('.ql-toolbar').first();
    await expect(toolbar).toBeVisible({ timeout: 5000 });

    // Check for Quill editor (contenteditable area)
    const editor = page.locator('.ql-editor').first();
    await expect(editor).toBeVisible({ timeout: 5000 });

    // Verify toolbar has buttons
    const toolbarButtons = page.locator('.ql-toolbar button');
    expect(await toolbarButtons.count()).toBeGreaterThan(0);
  });

  test('should be able to type content in Quill editor', async ({ page }) => {
    // Navigate to create new blog post
    await navigateToAdminSection(page, 'content');
    await page.click('a[href="/admin/content/new"]');
    await page.waitForURL('/admin/content/new', { timeout: 10000 });

    await page.click('text=Blog Posts');

    // Wait for Quill to load
    await page.waitForSelector('input[name="title"]', { timeout: 10000 });
    await page.waitForTimeout(2000);

    // Fill in title first
    await page.fill('input[name="title"]', 'Quill Test Post');

    // Wait for Quill editor to be visible
    const editor = page.locator('.ql-editor').first();
    await expect(editor).toBeVisible({ timeout: 5000 });

    // Click into the Quill editor
    await editor.click();

    // Type content into the editor
    const testContent = 'This is test content from Quill editor';
    await editor.fill(testContent);

    // Verify content was entered
    await expect(editor).toContainText(testContent);
  });

  test('should have Quill toolbar buttons functional', async ({ page }) => {
    await navigateToAdminSection(page, 'content');
    await page.click('a[href="/admin/content/new"]');
    await page.waitForURL('/admin/content/new', { timeout: 10000 });

    await page.click('text=Blog Posts');

    await page.waitForSelector('input[name="title"]', { timeout: 10000 });
    await page.waitForTimeout(2000);

    // Check for Quill toolbar
    const toolbar = page.locator('.ql-toolbar').first();
    await expect(toolbar).toBeVisible({ timeout: 5000 });

    // Check for specific toolbar buttons (Quill uses class names)
    const boldButton = page.locator('.ql-toolbar button.ql-bold').first();
    const italicButton = page.locator('.ql-toolbar button.ql-italic').first();

    // These buttons should be visible
    await expect(boldButton).toBeVisible();
    await expect(italicButton).toBeVisible();

    // Verify buttons are clickable
    await expect(boldButton).toBeEnabled();
    await expect(italicButton).toBeEnabled();
  });

  test('should save content from Quill editor', async ({ page }) => {
    await navigateToAdminSection(page, 'content');
    await page.click('a[href="/admin/content/new"]');
    await page.waitForURL('/admin/content/new', { timeout: 10000 });

    await page.click('text=Blog Posts');

    await page.waitForSelector('input[name="title"]', { timeout: 10000 });
    await page.waitForTimeout(2000);

    // Fill in title
    const uniqueTitle = `Quill Test ${Date.now()}`;
    await page.fill('input[name="title"]', uniqueTitle);

    // Wait for Quill editor
    const editor = page.locator('.ql-editor').first();
    await expect(editor).toBeVisible({ timeout: 5000 });

    // Add content to Quill editor
    const testContent = 'This is rich text content from Quill editor';
    await editor.click();
    await editor.fill(testContent);

    // Verify content is in the editor
    await expect(editor).toContainText(testContent);

    // Submit the form
    const saveButton = page.locator('button[type="submit"]:has-text("Save"), button:has-text("Create")');
    await saveButton.click();

    // Wait for redirect or success message
    await page.waitForTimeout(2000);

    // Verify we're back at content list or see success message
    const isContentList = await page.locator('h1:has-text("Content Management")').count() > 0;
    const hasSuccessMessage = await page.locator('.bg-green-100, text=successfully, text=created').count() > 0;

    expect(isContentList || hasSuccessMessage).toBeTruthy();
  });

  test('should apply bold formatting in Quill editor', async ({ page }) => {
    await navigateToAdminSection(page, 'content');
    await page.click('a[href="/admin/content/new"]');
    await page.waitForURL('/admin/content/new', { timeout: 10000 });

    await page.click('text=Blog Posts');

    await page.waitForSelector('input[name="title"]', { timeout: 10000 });
    await page.waitForTimeout(2000);

    // Fill in title
    await page.fill('input[name="title"]', 'Quill Bold Test');

    // Get Quill editor
    const editor = page.locator('.ql-editor').first();
    await expect(editor).toBeVisible({ timeout: 5000 });

    // Type some content
    await editor.click();
    await editor.type('Bold text test');

    // Select all text
    await page.keyboard.press('Control+A');

    // Click bold button
    const boldButton = page.locator('.ql-toolbar button.ql-bold').first();
    await boldButton.click();

    // Check if text is now bold (Quill adds <strong> or <b> tags)
    const boldText = editor.locator('strong, b');
    await expect(boldText).toBeVisible();
  });
});
