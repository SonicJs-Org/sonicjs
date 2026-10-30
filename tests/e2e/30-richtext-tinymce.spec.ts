import { test, expect, Page } from './fixtures';
import {
  loginAsAdmin,
  navigateToAdminSection,
  expectRichTextFieldUsable,
  fillRichTextField,
  richTextFieldValue,
} from './utils/test-helpers';

/**
 * TinyMCE is an optional editor plugin. `renderDynamicField` decides, server-side, which
 * editor backs a rich text field and marks the slot with
 * `.richtext-container[data-editor-provider="tinymce"]`; the TinyMCE CDN bundle then mounts
 * `.tox-tinymce` into exactly those slots. When no rich text plugin is active the field
 * degrades to an amber-bannered plain <textarea>.
 *
 * "TinyMCE slot absent" is NOT the same as "plain textarea". There are three states, and on a
 * fresh install the middle one is what renders: Lexical is the default rich text editor, so the
 * field is a contenteditable surface plus a hidden input and `textarea[name="content"]` does not
 * exist at all. Only with *no* editor plugin active does the field degrade to an amber-bannered
 * plain <textarea>. Asserting a textarea in the else branch is what made this spec pass locally
 * (no editor plugin rows) and fail on a fresh CI preview (Lexical active).
 *
 * Each test therefore asserts the branch the server actually rendered:
 *   TinyMCE slot present -> TinyMCE must really mount (container, toolbar, buttons, typing)
 *   TinyMCE slot absent  -> no TinyMCE chrome may leak in, and whichever editor did render must
 *                           still back a usable, submittable field (`expectRichTextFieldUsable`)
 * Both branches are falsifiable, and the discriminator is server-rendered markup rather than
 * plugin state, so these specs are safe to run alongside the /admin/plugins specs.
 */
const TINYMCE_SLOT = '.richtext-container[data-editor-provider="tinymce"]';

async function tinymceBacksField(page: Page): Promise<boolean> {
  return (await page.locator(TINYMCE_SLOT).count()) > 0;
}

/**
 * Walk the real "new content" path: content list -> collection picker -> collection form.
 * `/admin/content` no longer has a bare `a[href="/admin/content/new"]` link; every link is
 * `/admin/content/new?collection=<slug>` and slugs use underscores (`blog_post`).
 */
async function openNewContentForm(page: Page, collection: string) {
  await navigateToAdminSection(page, 'content');
  await expect(page.locator('h1')).toContainText('Content Management');

  await page.goto('/admin/content/new', { waitUntil: 'domcontentloaded' });
  await expect(page.locator('h1')).toContainText('Create New Content');

  await page.click(`a[href="/admin/content/new?collection=${collection}"]`);
  await page.waitForURL(new RegExp(`/admin/content/new\\?collection=${collection}`), { timeout: 15000 });
  await page.waitForSelector('input[name="title"]', { timeout: 15000 });
}

/**
 * blog_post requires title, slug, content and author. The author field is a user picker
 * whose submit handler re-reads the visible search box, so the display value, its
 * `dataset.linkedName` and the hidden input must all agree for the value to stick.
 */
async function fillRequiredBlogPostFields(page: Page, title: string) {
  await page.fill('input[name="title"]', title);
  await expect(page.locator('input[name="slug"]')).not.toHaveValue('');

  await page.evaluate(() => {
    const container = document.querySelector('.user-search-field-container');
    const display = container?.querySelector('input[type="text"]') as HTMLInputElement | null;
    const hidden = container?.querySelector('input[type="hidden"]') as HTMLInputElement | null;
    if (display) {
      display.value = 'Test Author';
      display.dataset.linkedName = 'Test Author';
    }
    if (hidden) hidden.value = 'Test Author';
  });
}

test.describe('Rich Text Editor (TinyMCE) @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should load TinyMCE for blog post content field', async ({ page }) => {
    await openNewContentForm(page, 'blog_post');

    if (await tinymceBacksField(page)) {
      // TinyMCE must take the field over: container, toolbar and toolbar buttons
      await expect(page.locator('.tox-tinymce').first()).toBeVisible({ timeout: 15000 });
      await expect(page.locator('.tox-toolbar, .tox-toolbar__primary').first()).toBeVisible({ timeout: 10000 });

      const toolbarButtons = page.locator('.tox-tbtn, button[aria-label*="Bold"], button[aria-label*="Italic"]');
      expect(await toolbarButtons.count()).toBeGreaterThan(0);
    } else {
      // No TinyMCE slot => no TinyMCE assets and no TinyMCE DOM, and the field still works
      await expect(page.locator('script[src*="tiny.cloud"]')).toHaveCount(0);
      await expect(page.locator('.tox-tinymce')).toHaveCount(0);
      await expectRichTextFieldUsable(page, 'content');
    }
  });

  test('should load TinyMCE for page content field', async ({ page }) => {
    // The old "Pages" collection no longer exists. E2E Test is the other collection carrying
    // a rich text field (`richContent`), so it covers the same "a second collection's rich
    // text field gets identical editor treatment" case.
    await openNewContentForm(page, 'e2e_test');

    if (await tinymceBacksField(page)) {
      await expect(page.locator('.tox-tinymce').first()).toBeVisible({ timeout: 15000 });
    } else {
      await expect(page.locator('script[src*="tiny.cloud"]')).toHaveCount(0);
      await expect(page.locator('.tox-tinymce')).toHaveCount(0);
      await expectRichTextFieldUsable(page, 'richContent');
    }
  });

  test('should be able to type content in TinyMCE editor', async ({ page }) => {
    await openNewContentForm(page, 'blog_post');
    await page.fill('input[name="title"]', 'TinyMCE Test Post');

    const testContent = 'This is test content from TinyMCE';

    if (await tinymceBacksField(page)) {
      if ((await page.locator('iframe[id*="content"]').count()) > 0) {
        // TinyMCE iframe mode
        const editorBody = page.frameLocator('iframe[id*="content"]').first().locator('body[id="tinymce"]');
        await editorBody.click();
        await editorBody.fill(`<p>${testContent}</p>`);
        await expect(editorBody).toContainText(testContent);
      } else {
        // TinyMCE inline mode
        const editableDiv = page.locator('.tox-tinymce [contenteditable="true"]').first();
        await expect(editableDiv).toBeVisible();
        await editableDiv.click();
        await editableDiv.fill(testContent);
        await expect(editableDiv).toContainText(testContent);
      }
    } else {
      // Whichever editor did render must accept the typed value and expose it on the control
      // the form submits.
      await expectRichTextFieldUsable(page, 'content');
      await fillRichTextField(page, 'content', testContent);
      expect(await richTextFieldValue(page, 'content')).toContain(testContent);
    }
  });

  test('should have TinyMCE toolbar buttons functional', async ({ page }) => {
    await openNewContentForm(page, 'blog_post');

    if (await tinymceBacksField(page)) {
      const boldButton = page.locator('button[aria-label*="Bold"], .tox-tbtn[aria-label*="Bold"]').first();
      const italicButton = page.locator('button[aria-label*="Italic"], .tox-tbtn[aria-label*="Italic"]').first();

      await expect(boldButton).toBeVisible({ timeout: 15000 });
      await expect(boldButton).toBeEnabled();
      await expect(italicButton).toBeVisible();
      await expect(italicButton).toBeEnabled();
    } else {
      // No TinyMCE chrome may be rendered, and the fallback field stays editable
      await expect(page.locator('.tox-toolbar, .tox-toolbar__primary')).toHaveCount(0);
      await expect(page.locator('.tox-tbtn')).toHaveCount(0);
      await expectRichTextFieldUsable(page, 'content');
    }
  });

  test('should save content from TinyMCE editor', async ({ page }) => {
    await openNewContentForm(page, 'blog_post');

    const uniqueTitle = `TinyMCE Test ${Date.now()}`;
    await fillRequiredBlogPostFields(page, uniqueTitle);

    const testContent = 'This is rich text content from TinyMCE editor';

    if ((await tinymceBacksField(page)) && (await page.locator('iframe[id*="content"]').count()) > 0) {
      const editorBody = page.frameLocator('iframe[id*="content"]').first().locator('body[id="tinymce"]');
      await editorBody.click();
      await editorBody.fill(`<p>${testContent}</p>`);
    } else {
      await fillRichTextField(page, 'content', testContent);
    }

    // A successful save redirects to the new document's edit page with a success flag; a
    // validation failure would keep us on /new, so the redirect proves the content persisted.
    await page.click('button[name="action"][value="save_and_close"]');

    await page.waitForURL(/\/admin\/content\/[^/]+\/edit\?success=/, { timeout: 20000 });
    await expect(page.locator('input[name="title"]')).toHaveValue(uniqueTitle);
    // The reloaded edit form re-renders the field through whichever editor is active.
    await expect(
      page.locator('textarea[name="content"], input[name="content"], iframe[id*="content"]').first()
    ).toBeAttached();
  });
});
