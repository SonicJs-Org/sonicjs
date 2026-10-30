import { test, expect } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

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
