import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe.skip('MDXEditor on New Content Form @content', () => {
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
    // Navigate to pages collection edit
    await page.goto('/admin/collections')
    await page.waitForLoadState('networkidle')

    // Find pages collection
    const pagesCollection = page.locator('tr').filter({ hasText: 'pages-collection' }).first()
    await expect(pagesCollection).toBeVisible()

    // Click edit
    await pagesCollection.locator('a[href*="/admin/collections/"]').first().click()
    await page.waitForLoadState('networkidle')

    // Check fields
    const fields = await page.locator('[data-field-row]').all()
    console.log('Total fields:', fields.length)

    for (const field of fields) {
      const fieldName = await field.locator('[data-field-name]').textContent()
      const fieldType = await field.locator('[data-field-type]').textContent()
      console.log(`Field: ${fieldName} - Type: ${fieldType}`)
    }

    // Look for richtext or markdown field
    const richtextField = page.locator('[data-field-row]').filter({
      hasText: /richtext|markdown|content/i
    })
    const richtextExists = await richtextField.count()
    console.log('Richtext/Content fields found:', richtextExists)

    if (richtextExists > 0) {
      const fieldType = await richtextField.first().locator('[data-field-type]').textContent()
      console.log('Content field type:', fieldType)
    }
  })

  test('should check mdxeditor plugin status and settings', async ({ page }) => {
    // Go to plugins page
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    // Find MDXEditor plugin
    const mdxPluginCard = page.locator('.plugin-card').filter({ hasText: /MDX.*Editor/i })
    const isVisible = await mdxPluginCard.isVisible()
    console.log('MDX Editor plugin card visible:', isVisible)

    if (isVisible) {
      // Check status
      const statusBadge = await mdxPluginCard.locator('[data-status]')
      const status = await statusBadge.textContent()
      console.log('MDX Editor status:', status)

      // Check if there's an activate/deactivate button
      const activateBtn = mdxPluginCard.locator('button:has-text("Activate")')
      const deactivateBtn = mdxPluginCard.locator('button:has-text("Deactivate")')

      const hasActivate = await activateBtn.count() > 0
      const hasDeactivate = await deactivateBtn.count() > 0

      console.log('Has Activate button:', hasActivate)
      console.log('Has Deactivate button:', hasDeactivate)

      // If not active, activate it
      if (hasActivate) {
        console.log('Activating MDXEditor plugin...')
        await activateBtn.click()
        await page.waitForTimeout(1000)

        // Verify activation
        const newStatus = await mdxPluginCard.locator('[data-status]').textContent()
        console.log('New status after activation:', newStatus)
      }
    } else {
      console.log('MDXEditor plugin not found in plugins list')

      // List all plugins
      const allPlugins = await page.locator('.plugin-card h3').allTextContents()
      console.log('Available plugins:', allPlugins)
    }
  })
})
