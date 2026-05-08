import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('EasyMDE Plugin Visibility', () => {
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

  test('should check plugin bootstrap logs', async ({ page }) => {
    // Capture console messages
    const consoleMessages: string[] = []
    page.on('console', msg => {
      const text = msg.text()
      if (text.includes('Plugin') || text.includes('bootstrap')) {
        consoleMessages.push(text)
      }
    })

    // Navigate to plugins page to trigger any bootstrap
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')
    await page.waitForTimeout(2000)

    // Log captured messages
    console.log('Bootstrap-related console messages:')
    consoleMessages.forEach(msg => console.log(msg))

    // Check page for plugin installation status
    const pageText = await page.textContent('body')
    console.log('Page contains "EasyMDE":', pageText?.includes('EasyMDE'))
    console.log('Page contains "mdxeditor":', pageText?.includes('mdxeditor'))
  })

  test('should verify plugin in database via API', async ({ page }) => {
    // Try to fetch plugin data via API if available
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    // Check network requests
    const requests: string[] = []
    page.on('request', request => {
      if (request.url().includes('plugin')) {
        requests.push(request.url())
      }
    })

    await page.reload()
    await page.waitForTimeout(1000)

    console.log('Plugin-related API requests:')
    requests.forEach(url => console.log(url))
  })
})
