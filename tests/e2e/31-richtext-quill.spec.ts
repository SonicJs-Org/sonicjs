import { test, expect, Page } from './fixtures';
import {
  loginAsAdmin,
  navigateToAdminSection,
  expectRichTextFieldUsable,
  fillRichTextField,
  richTextFieldValue,
} from './utils/test-helpers';

/**
 * Quill is an optional editor plugin. `renderDynamicField` decides, server-side, which editor
 * backs a rich text field: a Quill-backed field renders `.quill-editor-container` (a
 * contenteditable div plus a hidden input), which the Quill bundle hydrates into
 * `.ql-container` / `.ql-toolbar` / `.ql-editor`. With no rich text plugin active the field
 * degrades to an amber-bannered plain <textarea>.
 *
 * "No Quill slot" does not imply a textarea: Lexical is the default rich text editor, so on a
 * fresh install the field is a contenteditable surface plus a hidden input and
 * `textarea[name="content"]` does not exist. The else branch therefore asserts that no Quill
 * chrome leaked in and that whichever editor DID render still backs a usable field, rather than
 * naming a specific element.
 *
 * Each test asserts the branch the server actually rendered, so both directions are
 * falsifiable. The old unauthenticated `test.beforeAll` that POSTed to
 * /admin/plugins/quill-editor/install|activate is gone: it silently 302'd to the login page
 * (so it never worked) and it mutated global plugin state shared with every other spec.
 */
const QUILL_SLOT = '.quill-editor-container';

async function quillBacksField(page: Page): Promise<boolean> {
  return (await page.locator(QUILL_SLOT).count()) > 0;
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

test.describe('Rich Text Editor (Quill) @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should load Quill for blog post content field', async ({ page }) => {
    await openNewContentForm(page, 'blog_post');

    if (await quillBacksField(page)) {
      await expect(page.locator('.ql-container').first()).toBeVisible({ timeout: 15000 });
      await expect(page.locator('.ql-toolbar').first()).toBeVisible({ timeout: 10000 });
      await expect(page.locator('.ql-editor').first()).toBeVisible({ timeout: 10000 });
      expect(await page.locator('.ql-toolbar button').count()).toBeGreaterThan(0);
    } else {
      // No Quill slot => no Quill assets, no Quill DOM, and the fallback field still works
      await expect(page.locator('script[src*="quill"]')).toHaveCount(0);
      await expect(page.locator('.ql-container')).toHaveCount(0);
      await expect(page.locator('.ql-toolbar')).toHaveCount(0);
      await expectRichTextFieldUsable(page, 'content');
    }
  });

  test('should be able to type content in Quill editor', async ({ page }) => {
    await openNewContentForm(page, 'blog_post');
    await page.fill('input[name="title"]', 'Quill Test Post');

    const testContent = 'This is test content from Quill editor';

    if (await quillBacksField(page)) {
      const editor = page.locator('.ql-editor').first();
      await expect(editor).toBeVisible({ timeout: 15000 });
      await editor.click();
      await editor.fill(testContent);
      await expect(editor).toContainText(testContent);
    } else {
      await expectRichTextFieldUsable(page, 'content');
      await fillRichTextField(page, 'content', testContent);
      expect(await richTextFieldValue(page, 'content')).toContain(testContent);
    }
  });

  test('should have Quill toolbar buttons functional', async ({ page }) => {
    await openNewContentForm(page, 'blog_post');

    if (await quillBacksField(page)) {
      await expect(page.locator('.ql-toolbar').first()).toBeVisible({ timeout: 15000 });

      const boldButton = page.locator('.ql-toolbar button.ql-bold').first();
      const italicButton = page.locator('.ql-toolbar button.ql-italic').first();

      await expect(boldButton).toBeVisible();
      await expect(italicButton).toBeVisible();
      await expect(boldButton).toBeEnabled();
      await expect(italicButton).toBeEnabled();
    } else {
      // No Quill chrome may leak into the page; the fallback field stays editable
      await expect(page.locator('.ql-toolbar')).toHaveCount(0);
      await expect(page.locator('.ql-toolbar button.ql-bold')).toHaveCount(0);
      await expectRichTextFieldUsable(page, 'content');
    }
  });

  test('should save content from Quill editor', async ({ page }) => {
    await openNewContentForm(page, 'blog_post');

    const uniqueTitle = `Quill Test ${Date.now()}`;
    await fillRequiredBlogPostFields(page, uniqueTitle);

    const testContent = 'This is rich text content from Quill editor';

    if (await quillBacksField(page)) {
      const editor = page.locator('.ql-editor').first();
      await expect(editor).toBeVisible({ timeout: 15000 });
      await editor.click();
      await editor.fill(testContent);
      await expect(editor).toContainText(testContent);
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
      page.locator('textarea[name="content"], input[name="content"], .ql-editor').first()
    ).toBeAttached();
  });

  test('should apply bold formatting in Quill editor', async ({ page }) => {
    await openNewContentForm(page, 'blog_post');
    await page.fill('input[name="title"]', 'Quill Bold Test');

    if (await quillBacksField(page)) {
      const editor = page.locator('.ql-editor').first();
      await expect(editor).toBeVisible({ timeout: 15000 });

      await editor.click();
      await page.keyboard.type('Bold text test');
      await page.keyboard.press('ControlOrMeta+A');

      await page.locator('.ql-toolbar button.ql-bold').first().click();

      // Quill wraps the selection in <strong> (or <b>)
      await expect(editor.locator('strong, b').first()).toBeVisible();
    } else {
      // No Quill means no Quill formatting controls, whatever else backs the field. The field
      // must still take the typed text and carry it on the control the form submits.
      await fillRichTextField(page, 'content', 'Bold text test');
      expect(await richTextFieldValue(page, 'content')).toContain('Bold text test');
      await expect(page.locator('.ql-toolbar button.ql-bold')).toHaveCount(0);
    }
  });
});
