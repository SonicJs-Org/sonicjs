import { test } from "./fixtures"
import { expect } from "./fixtures"
import type { Page } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { navigateToAdminSection } from "./utils/test-helpers"
import { expectRichTextFieldUsable } from "./utils/test-helpers"
import { fillRichTextField } from "./utils/test-helpers"
import { richTextFieldValue } from "./utils/test-helpers"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 30-richtext-tinymce.spec.ts", () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 31-richtext-quill.spec.ts", () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 32-mdxeditor-new-content.spec.ts", () => {
  test.describe('MDXEditor on New Content Form @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('should load MDXEditor on new pages content form', async ({ page }) => {
      // Navigate to new content form for pages collection
      await page.goto('/admin/content/new?collection=pages-collection')
      await page.waitForLoadState('networkidle')

      // Wait a bit for scripts to load
      await page.waitForTimeout(2000)

      // Check page title
      await expect(page.locator('h1')).toContainText('New')

      // Log all script tags to see what's loaded
      const scripts = await page.$$eval('script[src]', scripts =>
        scripts.map(s => s.getAttribute('src'))
      )
      console.log('Scripts loaded:', scripts)

      // Check if EasyMDE script is loaded
      const hasEasyMDE = scripts.some(src =>
        src?.includes('easymde') || src?.includes('EasyMDE')
      )
      console.log('Has EasyMDE script:', hasEasyMDE)

      // Check if there's a richtext field
      const richtextFields = await page.locator('[data-field-type="richtext"]').count()
      console.log('Richtext fields found:', richtextFields)

      // Check for EasyMDE container
      const easyMDEExists = await page.locator('.CodeMirror').count()
      console.log('EasyMDE containers found:', easyMDEExists)

      // Check browser console for any errors
      const consoleMessages: string[] = []
      page.on('console', msg => {
        consoleMessages.push(`${msg.type()}: ${msg.text()}`)
      })

      // Check if mdxeditorEnabled is passed to the template
      const pageContent = await page.content()
      console.log('mdxeditorEnabled in page:', pageContent.includes('mdxeditorEnabled'))
      console.log('mdxeditorSettings in page:', pageContent.includes('mdxeditorSettings'))

      // Take a screenshot for debugging
      await page.screenshot({ path: 'test-results/mdxeditor-new-content.png', fullPage: true })

      // Log console messages
      await page.waitForTimeout(1000)
      console.log('Console messages:', consoleMessages)

      // Expect EasyMDE to be loaded
      if (hasEasyMDE) {
        expect(easyMDEExists).toBeGreaterThan(0)
      } else {
        console.log('EasyMDE script not found - checking why')

        // Check if plugin is active
        await page.goto('/admin/plugins')
        await page.waitForLoadState('networkidle')

        const mdxPluginCard = page.locator('.plugin-card').filter({ hasText: 'MDX Editor' })
        const isVisible = await mdxPluginCard.isVisible()
        console.log('MDX Editor plugin visible:', isVisible)

        if (isVisible) {
          const statusBadge = await mdxPluginCard.locator('[data-status]').textContent()
          console.log('MDX Editor plugin status:', statusBadge)
        }
      }
    })

    test('should check pages collection schema for richtext field', async ({ page }) => {
      // The old `pages-collection` is gone; collections are code-only and slugs use
      // underscores. blog_post is the collection that carries the rich text "content" field.
      await page.goto('/admin/collections', { waitUntil: 'domcontentloaded' })

      // Find blog_post collection (rows navigate via onclick, not an <a>)
      const pagesCollection = page.locator('tbody tr').filter({ hasText: 'blog_post' }).first()
      await expect(pagesCollection).toBeVisible({ timeout: 15000 })

      // Open it
      await pagesCollection.click()
      await page.waitForURL(/\/admin\/collections\/blog_post$/, { timeout: 15000 })
      await expect(page.locator('h1')).toContainText('Edit Collection')

      // Read the read-only field list rendered from the collection config
      const fields = page
        .locator('div.bg-zinc-50.rounded-lg.border.p-4')
        .filter({ has: page.locator('code.font-mono') })
      const fieldCount = await fields.count()
      expect(fieldCount).toBeGreaterThan(0)

      const schema: { name: string; type: string }[] = []
      for (let i = 0; i < fieldCount; i++) {
        const row = fields.nth(i)
        const fieldName = ((await row.locator('code.font-mono').first().textContent()) || '').trim()
        const fieldType = (
          (await row.locator('span.inline-flex.items-center.rounded-md').first().textContent()) || ''
        )
          .replace(/\s+/g, ' ')
          .trim()
        schema.push({ name: fieldName, type: fieldType })
      }

      // The collection must expose a rich-text content field, and every field must declare a type
      const contentField = schema.find((f) => f.name === 'content')
      expect(contentField, 'blog_post exposes a "content" field').toBeDefined()
      expect(contentField!.type).not.toBe('')
      expect(['lexical', 'richtext', 'markdown', 'Rich Text (TinyMCE)', 'Rich Text (Quill)', 'Markdown'])
        .toContain(contentField!.type)

      for (const field of schema) {
        expect(field.name, 'field name rendered').not.toBe('')
        expect(field.type, `type badge for ${field.name}`).not.toBe('')
      }
    })

    // This test used to be a script, not a test: every branch ended in console.log and it
    // made zero assertions, so it passed whether or not the plugin existed. It also clicked
    // "Activate" when it found the button -- mutating plugin state in the middle of a run,
    // with no verification, which is a cross-spec race rather than coverage. The toggle is
    // covered by 15-plugins; what belongs here is that the card is coherent.
    //
    // The old locator was `/MDX.*Editor/i`, which matches no plugin in the catalog -- the
    // markdown editor ships as `easy-mdx`, "EasyMDE Markdown Editor". So the test took its
    // "plugin not found" branch on every single run and printed a list of the plugins it
    // had failed to match. Nothing ever told anyone, because the branch logged and returned.
    test('shows a coherent install status for the markdown editor plugin', async ({ page }) => {
      await page.goto('/admin/plugins')
      await page.waitForLoadState('networkidle')

      const card = page.locator('.plugin-card').filter({ hasText: /EasyMDE/i }).first()
      await expect(card).toBeVisible()

      const status = await card.getAttribute('data-status')
      expect(['active', 'inactive', 'installed', 'uninstalled'], `unexpected status ${status}`).toContain(status)

      // The action offered has to match the state shown. A card claiming to be active while
      // offering "Activate" means the status badge and the button are reading different
      // sources -- which is how a plugin ends up looking installed while it is not.
      const hasActivate = (await card.locator('button:has-text("Activate")').count()) > 0
      const hasDeactivate = (await card.locator('button:has-text("Deactivate")').count()) > 0
      if (status === 'active') {
        expect(hasActivate, 'an active plugin offered an Activate button').toBe(false)
        expect(hasDeactivate, 'an active plugin offered no Deactivate button').toBe(true)
      } else if (status === 'inactive') {
        expect(hasActivate, 'an inactive plugin offered no Activate button').toBe(true)
      }
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 32-mdxeditor-richtext.spec.ts", () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 36-easymde-plugin-visible.spec.ts", () => {
  test.describe('EasyMDE Plugin Visibility @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('should show EasyMDE Editor plugin in plugins list', async ({ page }) => {
      // Navigate to plugins page
      await page.goto('/admin/plugins')
      await page.waitForLoadState('networkidle')

      // Take screenshot for debugging
      await page.screenshot({ path: 'test-results/plugins-list.png', fullPage: true })

      // Get all plugin cards
      const pluginCards = await page.locator('.plugin-card').all()
      console.log(`Total plugin cards found: ${pluginCards.length}`)

      // Log all plugin names
      for (const card of pluginCards) {
        const name = await card.locator('h3, [data-plugin-name]').textContent()
        console.log(`Plugin found: ${name}`)
      }

      // Check if EasyMDE Editor plugin exists
      const easyMDEPlugin = page.locator('.plugin-card').filter({
        hasText: /EasyMDE|mdxeditor/i
      })

      const count = await easyMDEPlugin.count()
      console.log(`EasyMDE plugin cards found: ${count}`)

      if (count === 0) {
        // Debug: Check database directly
        console.log('Plugin not found in UI, checking database...')

        // Navigate to a page that might show DB content
        const pageContent = await page.content()
        console.log('Page has plugin list:', pageContent.includes('plugin-card'))
      }

      // Expect at least one EasyMDE plugin card
      expect(count).toBeGreaterThan(0)
    })

    // Replaces two tests that asserted nothing at all -- one captured console messages and
    // printed them, the other recorded plugin-related request URLs and printed those. Both
    // passed unconditionally, including on a build where the plugin was missing entirely.
    //
    // What they were reaching for is worth keeping: the card has to reflect a real row read
    // out of the database, not a placeholder rendered from the manifest alone. `data-status`
    // is only ever one of these four values, and `uninstalled` is what the page falls back to
    // when no plugin document exists -- the exact state a half-finished bootstrap leaves
    // behind.
    test('reports a real install status read from the database', async ({ page }) => {
      await page.goto('/admin/plugins')
      await page.waitForLoadState('networkidle')

      const card = page.locator('.plugin-card').filter({ hasText: /EasyMDE|mdxeditor/i }).first()
      await expect(card).toBeVisible()

      const status = await card.getAttribute('data-status')
      expect(['active', 'inactive', 'installed', 'uninstalled'], `unexpected status ${status}`).toContain(status)
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 77-lexical-editor.spec.ts", () => {
  /**
   * Lexical is the default richtext editor, and `blog_post.content` is declared `type: 'lexical'`,
   * so `/admin/content/new?collection=blog_post` always renders a real editor. Every test in this
   * file used to hedge against it not being there — `if (await wrapper.count() === 0) return`,
   * nested `if`s, a `.catch(() => {})` on the init wait — so the file reported green while
   * asserting nothing about the editor at all.
   *
   * Two tests were deleted rather than hollowed out:
   *
   * - `lexical field type can be selected in collection schema editor` looked for a field-type
   *   `<select>` on `/admin/collections`. That page is a read-only list; collections are code-only
   *   (`registerCollections`), so there is no schema editor and no select to find. The test was
   *   `if (count > 0)` around its only assertion, i.e. a permanent no-op.
   * - `fallback textarea renders when lexical plugin is inactive` said so itself: "Since we can't
   *   easily deactivate the plugin in E2E, we just verify the plugin settings page is accessible."
   *   Deactivating the default editor mid-suite is shared global state that a concurrently running
   *   @content spec would see, and the fallback is a pure function of `pluginStatuses`, so it is
   *   covered in `__tests__/templates/dynamic-field-extended.test.ts` instead — where quill,
   *   mdxeditor and tinymce fallbacks already live.
   */

  const BLOG_POST_FORM = '/admin/content/new?collection=blog_post'

  /** The editor Lexical renders for `blog_post.content`. */
  const editor = (page: Page) => page.locator('.lexical-editor-wrapper').first()

  test.describe('Lexical Rich Text Editor Plugin @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('ships active on a fresh install', async ({ page }) => {
      await page.goto('/admin/plugins')

      // data-name carries the manifest's displayName, which is what the card renders.
      const card = page.locator('.plugin-card[data-name="Lexical Rich Text Editor"]')
      await expect(card).toHaveCount(1)
      await expect(card).toHaveAttribute('data-status', 'active')
      await expect(card.locator('.status-badge')).toContainText('Active')
    })

    test('renders the editor for a lexical field', async ({ page }) => {
      await page.goto(BLOG_POST_FORM)

      const wrapper = editor(page)
      await expect(wrapper).toBeVisible()
      await expect(wrapper).toHaveAttribute('data-field-id', 'field-content')

      await expect(wrapper.locator('.lexical-toolbar')).toBeVisible()

      const surface = wrapper.locator('.lexical-content-editable')
      await expect(surface).toBeVisible()
      await expect(surface).toHaveAttribute('contenteditable', 'true')
      await expect(surface).toHaveAttribute('role', 'textbox')

      // The hidden input is what the form actually submits; without it a typed post saves empty.
      await expect(wrapper.locator('input[type="hidden"][name="content"]')).toHaveCount(1)

      // These two only render when the server resolved the plugin as active, so they are the
      // server-side half of the "active by default" claim above.
      await expect(page.locator('#lexical-importmap')).toHaveCount(1)
      await expect(page.locator('#lexical-editor-styles')).toHaveCount(1)
    })

    test('renders the formatting actions the toolbar claims', async ({ page }) => {
      await page.goto(BLOG_POST_FORM)

      const toolbar = editor(page).locator('.lexical-toolbar')
      await expect(toolbar).toBeVisible()

      // bold/italic/link are in every toolbar preset, so asserting them does not pin the field to
      // one preset — it pins that the buttons the init script wires up actually exist.
      for (const action of ['bold', 'italic', 'link']) {
        await expect(
          toolbar.locator(`[data-action="${action}"]`),
          `toolbar is missing the ${action} button`
        ).toBeVisible()
      }

      // Every button must carry an action and a label: the click handler dispatches on
      // `data-action`, and a button whose only content is an icon is unreachable without the label.
      const buttons = toolbar.locator('.lexical-toolbar-btn')
      expect(await buttons.count()).toBeGreaterThan(2)
      for (const attr of ['data-action', 'aria-label']) {
        const values = await buttons.evaluateAll(
          (els, name) => els.map((el) => el.getAttribute(name as string) ?? ''),
          attr
        )
        expect(values.filter((v) => v === ''), `${attr} missing on a toolbar button`).toEqual([])
      }
    })

    test('typing fills the hidden input the form submits', async ({ page }) => {
      await page.goto(BLOG_POST_FORM)

      const wrapper = editor(page)
      await expect(wrapper).toBeVisible()

      // Lexical itself is fetched from esm.sh at runtime. Everything above is server-rendered and
      // unconditional; this test is the one part that cannot run without that fetch succeeding, so
      // it feature-detects rather than failing the suite on someone else's CDN.
      const ready = await wrapper
        .evaluate(
          (el) =>
            new Promise<boolean>((resolve) => {
              if (el.getAttribute('data-lexical-initialized') === 'true') return resolve(true)
              const timer = setTimeout(() => {
                observer.disconnect()
                resolve(false)
              }, 15_000)
              const observer = new MutationObserver(() => {
                if (el.getAttribute('data-lexical-initialized') === 'true') {
                  clearTimeout(timer)
                  observer.disconnect()
                  resolve(true)
                }
              })
              observer.observe(el, { attributes: true, attributeFilter: ['data-lexical-initialized'] })
            })
        )
        .catch(() => false)
      test.skip(!ready, 'Lexical loads from esm.sh — the CDN did not answer from this runner')

      const typed = `Hello Lexical ${Date.now()}`
      await wrapper.locator('.lexical-content-editable').click()
      await page.keyboard.type(typed)

      // `registerUpdateListener` writes `$generateHtmlFromNodes` into the hidden input on every
      // change, so the text has to show up there — that value is the one the POST carries.
      await expect
        .poll(() => wrapper.locator('input[type="hidden"][name="content"]').inputValue(), {
          message: 'the hidden input never picked up the typed text',
          timeout: 10_000,
        })
        .toContain(typed)
    })
  })
})
