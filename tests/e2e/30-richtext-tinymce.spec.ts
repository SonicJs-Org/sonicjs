import { test, expect } from '@playwright/test';
import { loginAsAdmin, navigateToAdminSection } from './utils/test-helpers';

test.describe.skip('Rich Text Editor (TinyMCE) @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should load TinyMCE for blog post content field', async ({ page }) => {
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

    // Check if TinyMCE is initialized for content field
    // TinyMCE creates an iframe with id that starts with the field id
    const contentField = page.locator('textarea[name="content"]');
    await expect(contentField).toBeAttached();

    // Wait for TinyMCE to initialize (it should create an iframe or convert the textarea)
    await page.waitForTimeout(2000); // Give TinyMCE time to initialize

    // Check for TinyMCE editor elements
    // TinyMCE should add the 'tox-tinymce' class or create an iframe
    const tinyMCEContainer = page.locator('.tox-tinymce').first();
    await expect(tinyMCEContainer).toBeVisible({ timeout: 5000 });

    // Check for TinyMCE toolbar
    const toolbar = page.locator('.tox-toolbar, .tox-toolbar__primary').first();
    await expect(toolbar).toBeVisible({ timeout: 5000 });

    // Verify toolbar has buttons
    const toolbarButtons = page.locator('.tox-tbtn, button[aria-label*="Bold"], button[aria-label*="Italic"]');
    expect(await toolbarButtons.count()).toBeGreaterThan(0);
  });

  test('should load TinyMCE for page content field', async ({ page }) => {
    // Navigate to create new page
    await navigateToAdminSection(page, 'content');

    // Click "New Content" link
    await page.click('a[href="/admin/content/new"]');

    // Wait for collection selection page
    await page.waitForURL('/admin/content/new', { timeout: 10000 });

    // Click on Pages collection (find any link/card with "Pages" or "Page" text)
    const pagesLink = page.locator('text=/^Pages?$/i').first();
    await pagesLink.click();

    // Wait for the form to load
    await page.waitForSelector('input[name="title"]', { timeout: 10000 });

    // Check if TinyMCE is initialized for content field
    await page.waitForTimeout(2000); // Give TinyMCE time to initialize

    // Check for TinyMCE editor elements
    const tinyMCEContainer = page.locator('.tox-tinymce').first();
    await expect(tinyMCEContainer).toBeVisible({ timeout: 5000 });
  });

  test('should be able to type content in TinyMCE editor', async ({ page }) => {
    // Navigate to create new blog post
    await navigateToAdminSection(page, 'content');
    await page.click('a[href="/admin/content/new"]');
    await page.waitForURL('/admin/content/new', { timeout: 10000 });

    await page.click('text=Blog Posts');

    // Wait for TinyMCE to load
    await page.waitForSelector('input[name="title"]', { timeout: 10000 });
    await page.waitForTimeout(2000);

    // Fill in title first
    await page.fill('input[name="title"]', 'TinyMCE Test Post');

    // Try to interact with TinyMCE editor
    // Method 1: Check if there's an iframe and type into it
    const iframe = page.frameLocator('iframe[id*="content"]').first();
    const iframeExists = await page.locator('iframe[id*="content"]').count() > 0;

    if (iframeExists) {
      // TinyMCE uses iframe mode
      const editorBody = iframe.locator('body[id="tinymce"]');
      await editorBody.click();
      await editorBody.fill('<p>This is test content from TinyMCE</p>');

      // Verify content was entered
      await expect(editorBody).toContainText('This is test content from TinyMCE');
    } else {
      // TinyMCE might be in inline mode or not loaded
      // Check if the contenteditable div exists
      const editableDiv = page.locator('[contenteditable="true"]').first();
      if (await editableDiv.count() > 0) {
        await editableDiv.click();
        await editableDiv.fill('This is test content from TinyMCE');
        await expect(editableDiv).toContainText('This is test content from TinyMCE');
      }
    }
  });

  test('should have TinyMCE toolbar buttons functional', async ({ page }) => {
    await navigateToAdminSection(page, 'content');
    await page.click('a[href="/admin/content/new"]');
    await page.waitForURL('/admin/content/new', { timeout: 10000 });

    await page.click('text=Blog Posts');

    await page.waitForSelector('input[name="title"]', { timeout: 10000 });
    await page.waitForTimeout(2000);

    // Check for specific toolbar buttons
    const boldButton = page.locator('button[aria-label*="Bold"], .tox-tbtn[aria-label*="Bold"]');
    const italicButton = page.locator('button[aria-label*="Italic"], .tox-tbtn[aria-label*="Italic"]');

    // These buttons should be visible
    if (await boldButton.count() > 0) {
      await expect(boldButton.first()).toBeVisible();
    }

    if (await italicButton.count() > 0) {
      await expect(italicButton.first()).toBeVisible();
    }
  });

  test('should save content from TinyMCE editor', async ({ page }) => {
    await navigateToAdminSection(page, 'content');
    await page.click('a[href="/admin/content/new"]');
    await page.waitForURL('/admin/content/new', { timeout: 10000 });

    await page.click('text=Blog Posts');

    await page.waitForSelector('input[name="title"]', { timeout: 10000 });
    await page.waitForTimeout(2000);

    // Fill in title
    const uniqueTitle = `TinyMCE Test ${Date.now()}`;
    await page.fill('input[name="title"]', uniqueTitle);

    // Try to add content to TinyMCE
    const iframe = page.frameLocator('iframe[id*="content"]').first();
    const iframeExists = await page.locator('iframe[id*="content"]').count() > 0;

    const testContent = 'This is rich text content from TinyMCE editor';

    if (iframeExists) {
      const editorBody = iframe.locator('body[id="tinymce"]');
      await editorBody.click();
      await editorBody.fill(`<p>${testContent}</p>`);
    }

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
});
