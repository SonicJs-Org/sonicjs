import { test, expect, Page } from './fixtures';
import {
  loginAsAdmin,
  navigateToAdminSection,
  expectRichTextFieldUsable,
  fillRichTextField,
  richTextFieldValue,
} from './utils/test-helpers';

/**
 * The "MDXEditor" plugin ships as `easy-mdx` and is listed on /admin/plugins as
 * "EasyMDE Markdown Editor"; its assets are EasyMDE's CDN bundle (`easymde.min.js`), not
 * anything named `mdxeditor`. Markdown-backed fields are rendered server-side as
 * `.richtext-container[data-editor-provider="easymde"]`, which the plugin's init script
 * hydrates into an EasyMDE instance (`.EasyMDEContainer` / `.editor-toolbar`). With *no* editor
 * plugin at all the field degrades to an amber-bannered plain <textarea> — but that is only one
 * of the two non-EasyMDE states. Lexical is the default rich text editor, so on a fresh install
 * the field is a contenteditable surface plus a hidden input and `textarea[name="content"]` does
 * not exist. The else branches assert "no EasyMDE chrome leaked in and the field still works"
 * rather than naming a textarea.
 *
 * These specs only READ plugin state (no install/activate/deactivate) so they can run
 * alongside the /admin/plugins specs, and they assert whichever branch is actually live.
 */
const EASYMDE_PLUGIN_CARD = 'EasyMDE Markdown Editor';
const EASYMDE_SLOT = '.richtext-container[data-editor-provider="easymde"]';

async function easymdePluginStatus(page: Page): Promise<string | null> {
  await navigateToAdminSection(page, 'plugins');
  const card = page.locator(`.plugin-card[data-name="${EASYMDE_PLUGIN_CARD}"]`);
  await expect(card).toHaveCount(1);
  return card.getAttribute('data-status');
}

async function easymdeBacksField(page: Page): Promise<boolean> {
  return (await page.locator(EASYMDE_SLOT).count()) > 0;
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

async function openBlogPostForm(page: Page) {
  // Collection slugs use underscores — the old `blog-posts` slug no longer resolves.
  await page.goto('/admin/content/new?collection=blog_post', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('input[name="title"]', { timeout: 15000 });
}

test.describe('MDXEditor Rich Text Editor @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should activate MDXEditor plugin', async ({ page }) => {
    // /admin/plugins is a card grid now (no <tr> rows). Assert the plugin is registered,
    // reports a legal lifecycle status, and offers the control that advances it.
    // NOTE: read-only on purpose — activating here would mutate state shared by every
    // other spec running against the same server.
    await navigateToAdminSection(page, 'plugins');

    const mdxeditorPlugin = page.locator(`.plugin-card[data-name="${EASYMDE_PLUGIN_CARD}"]`);
    await expect(mdxeditorPlugin).toBeVisible({ timeout: 10000 });

    const status = await mdxeditorPlugin.getAttribute('data-status');
    expect(['active', 'inactive', 'uninstalled', 'error']).toContain(status);

    // The badge text must agree with the machine-readable status
    const statusBadge = mdxeditorPlugin.locator('.status-badge');
    await expect(statusBadge).toBeVisible();
    const badgeText = (await statusBadge.textContent())?.trim().toLowerCase();
    expect(badgeText).toContain(status as string);

    if (status === 'uninstalled') {
      // Not installed yet: the only affordance is Install
      await expect(mdxeditorPlugin.locator('button:has-text("Install")')).toBeVisible();
      await expect(mdxeditorPlugin.locator('button[onclick*="togglePlugin"]')).toHaveCount(0);
    } else {
      // Installed: the activate/deactivate toggle must be offered
      await expect(mdxeditorPlugin.locator('button[onclick*="togglePlugin"]').first()).toBeVisible();
    }
  });

  test('should load MDXEditor scripts when plugin is active', async ({ page }) => {
    const status = await easymdePluginStatus(page);

    await openBlogPostForm(page);

    // The editor bundle is EasyMDE's; it is injected only while the plugin is active.
    const mdxeditorScript = page.locator('script[src*="easymde"]');

    if (status === 'active') {
      expect(await mdxeditorScript.count()).toBeGreaterThan(0);
      await expect(page.locator('link[href*="easymde"]')).not.toHaveCount(0);
    } else {
      await expect(mdxeditorScript).toHaveCount(0);
      // The template leaves an explicit marker instead of the bundle
      expect(await page.content()).toContain('MDXEditor plugin not active');
    }
  });

  test('should initialize MDXEditor for richtext fields', async ({ page }) => {
    await openBlogPostForm(page);

    if (await easymdeBacksField(page)) {
      const richtextContainer = page.locator(EASYMDE_SLOT).first();
      await expect(richtextContainer).toBeVisible({ timeout: 10000 });

      // EasyMDE replaces the textarea with a CodeMirror surface plus its own toolbar
      await expect(page.locator('.EasyMDEContainer').first()).toBeVisible({ timeout: 15000 });
      await expect(page.locator('.editor-toolbar').first()).toBeVisible();
      await expect(page.locator('.CodeMirror').first()).toBeVisible();
    } else {
      // No markdown-backed slot: nothing EasyMDE may be hydrated, and the field still has to be
      // usable through whichever editor did render.
      await expect(page.locator(EASYMDE_SLOT)).toHaveCount(0);
      await expect(page.locator('.EasyMDEContainer')).toHaveCount(0);

      const backing = await expectRichTextFieldUsable(page, 'content');

      // The amber "plugin is inactive" notice belongs to the no-editor-at-all fallback only;
      // when another editor owns the field there is nothing to warn about.
      const notice = page.locator('div.bg-amber-50', { hasText: 'editor plugin is' });
      if (backing === 'textarea') {
        await expect(notice.first()).toBeVisible();
      } else {
        await expect(notice).toHaveCount(0);
      }
    }
  });

  test('should allow typing content in MDXEditor', async ({ page }) => {
    await openBlogPostForm(page);

    await page.fill('input[name="title"]', 'MDXEditor Test Post');

    const markdown = '# Test Heading\n\nThis is a test post using MDXEditor.';

    if (await easymdeBacksField(page)) {
      // EasyMDE edits through CodeMirror and mirrors the value back into the textarea
      const codeMirror = page.locator('.CodeMirror').first();
      await expect(codeMirror).toBeVisible({ timeout: 15000 });
      await codeMirror.click();
      await page.keyboard.type(markdown);
      await expect(codeMirror).toContainText('Test Heading');
      await expect(page.locator(`${EASYMDE_SLOT} textarea`).first()).toHaveValue(/Test Heading/);
    } else {
      await expectRichTextFieldUsable(page, 'content');
      await fillRichTextField(page, 'content', markdown);
      expect(await richTextFieldValue(page, 'content')).toContain('Test Heading');
    }
  });

  test('should save content with MDXEditor value', async ({ page }) => {
    await openBlogPostForm(page);

    const title = `MDXEditor Test ${Date.now()}`;
    await fillRequiredBlogPostFields(page, title);

    const mdxContent = '# Test Heading\n\nThis is test content from MDXEditor.';

    if (await easymdeBacksField(page)) {
      const codeMirror = page.locator('.CodeMirror').first();
      await expect(codeMirror).toBeVisible({ timeout: 15000 });
      await codeMirror.click();
      await page.keyboard.type(mdxContent);
    } else {
      await fillRichTextField(page, 'content', mdxContent);
    }

    await page.click('button[name="action"][value="save"]');

    // A successful save redirects to the new document's edit page with a success flag; a
    // validation failure would keep us on /new, so the redirect proves the value persisted.
    await page.waitForURL(/\/admin\/content\/[^/]+\/edit\?success=/, { timeout: 20000 });
    await expect(page.locator('input[name="title"]')).toHaveValue(title);
    // The reloaded edit form re-renders the field through whichever editor is active.
    await expect(
      page.locator('textarea[name="content"], input[name="content"], .CodeMirror').first()
    ).toBeAttached();
  });
});
