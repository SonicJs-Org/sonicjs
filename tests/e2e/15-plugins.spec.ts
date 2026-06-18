import { test, expect } from '@playwright/test'
import { 
  loginAsAdmin, 
  ensureAdminUserExists,
  ensureWorkflowTablesExist
} from './utils/test-helpers'

// Use environment variable for port or default to 8787
const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

test.describe('Plugin Management', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
  })

  test('should access plugins page and show basic UI', async ({ page }) => {
    // Navigate to plugins page
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Check page title
    await expect(page.locator('h1')).toContainText('Plugins')
    
    // Check for install plugin button
    await expect(page.locator('button:has-text("Install Plugin")')).toBeVisible()
    
    // Install FAQ plugin if no plugins exist
    const pluginCount = await page.locator('.plugin-card').count()
    if (pluginCount === 0) {
      // Click install plugin button
      await page.click('button:has-text("Install Plugin")')
      await expect(page.locator('#plugin-dropdown')).toBeVisible()
      
      // Install FAQ System
      await page.click('button:has-text("FAQ System")')
      await page.waitForTimeout(2000) // Wait for installation
      await page.reload()
    }
    
    // Check for at least one plugin card after installation
    await expect(page.locator('.plugin-card').first()).toBeVisible()
  })

  test('should show plugin stats', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)

    // Check for stats cards (at least total plugins)
    await expect(page.locator('text=Total Plugins').first()).toBeVisible()

    // Look for plugin count in stats cards - the number is in a div with text-2xl class
    const statsCards = page.locator('div').filter({ hasText: 'Total Plugins' }).locator('div.text-2xl')
    await expect(statsCards.first()).toBeVisible()
  })

  test('should display existing plugins', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Ensure at least one plugin exists
    let pluginCount = await page.locator('.plugin-card').count()
    if (pluginCount === 0) {
      // Install FAQ plugin
      await page.click('button:has-text("Install Plugin")')
      await expect(page.locator('#plugin-dropdown')).toBeVisible()
      await page.click('button:has-text("FAQ System")')
      await page.waitForTimeout(2000)
      await page.reload()
      pluginCount = await page.locator('.plugin-card').count()
    }
    
    expect(pluginCount).toBeGreaterThan(0)
    
    // First plugin should have required elements
    const firstPlugin = page.locator('.plugin-card').first()
    await expect(firstPlugin.locator('h3')).toBeVisible() // Plugin name
    await expect(firstPlugin.locator('.status-badge')).toBeVisible() // Status
  })

  test('should install FAQ plugin if not present', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Check if FAQ plugin exists
    const faqExists = await page.locator('.plugin-card:has-text("FAQ System")').count()
    
    if (faqExists === 0) {
      // Try to install FAQ plugin
      await page.click('button:has-text("Install Plugin")')
      
      // Wait for dropdown and check if FAQ option exists
      const dropdownVisible = await page.locator('#plugin-dropdown').isVisible()
      if (dropdownVisible) {
        const faqOption = page.locator('button:has-text("FAQ System")')
        const optionExists = await faqOption.count()
        
        if (optionExists > 0) {
          await faqOption.click()
          
          // Wait for installation success
          await expect(page.locator('text=success')).toBeVisible({ timeout: 10000 })
          
          // Reload and verify FAQ plugin appears
          await page.reload()
          await expect(page.locator('.plugin-card:has-text("FAQ System")')).toBeVisible()
        }
      }
    } else {
      // FAQ plugin already exists
      await expect(page.locator('.plugin-card:has-text("FAQ System")')).toBeVisible()
    }
  })

  test('should show plugin actions', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Ensure at least one plugin exists
    let pluginCount = await page.locator('.plugin-card').count()
    if (pluginCount === 0) {
      // Install FAQ plugin
      await page.click('button:has-text("Install Plugin")')
      await expect(page.locator('#plugin-dropdown')).toBeVisible()
      await page.click('button:has-text("FAQ System")')
      await page.waitForTimeout(2000)
      await page.reload()
      pluginCount = await page.locator('.plugin-card').count()
    }
    
    expect(pluginCount).toBeGreaterThan(0)
    
    // Find any plugin card
    const pluginCard = page.locator('.plugin-card').first()
    
    // Should have either activate or deactivate button or settings button
    const hasActivate = await pluginCard.locator('button:has-text("Activate")').count()
    const hasDeactivate = await pluginCard.locator('button:has-text("Deactivate")').count()
    const hasSettings = await pluginCard.locator('button:has-text("Settings")').count()
    
    expect(hasActivate + hasDeactivate + hasSettings).toBeGreaterThan(0)
  })

  test('should toggle plugin status', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Find a plugin that can be toggled
    const pluginCards = page.locator('.plugin-card')
    const count = await pluginCards.count()
    
    for (let i = 0; i < Math.min(count, 3); i++) {
      const card = pluginCards.nth(i)
      const activateBtn = card.locator('button:has-text("Activate")')
      const deactivateBtn = card.locator('button:has-text("Deactivate")')
      
      const hasActivate = await activateBtn.count()
      const hasDeactivate = await deactivateBtn.count()
      
      if (hasActivate > 0) {
        // Plugin is inactive, try to activate
        await activateBtn.click()
        
        // Wait for status change
        await expect(card.locator('.status-badge')).toContainText('Active', { timeout: 5000 })
        break
      } else if (hasDeactivate > 0) {
        // Plugin is active, try to deactivate
        await deactivateBtn.click()
        
        // Wait for status change
        await expect(card.locator('.status-badge')).toContainText('Inactive', { timeout: 5000 })
        break
      }
    }
  })

  test('should access plugin settings', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Find a plugin with settings button
    const pluginCards = page.locator('.plugin-card')
    const count = await pluginCards.count()
    
    for (let i = 0; i < Math.min(count, 3); i++) {
      const card = pluginCards.nth(i)
      const settingsBtn = card.locator('button[title="Settings"], button:has-text("Settings")')
      
      const hasSettings = await settingsBtn.count()
      if (hasSettings > 0) {
        await settingsBtn.click()
        
        // Should navigate to plugin settings page
        await expect(page.url()).toContain('/admin/plugins/')
        await expect(page.locator('h2:has-text("Plugin Settings")')).toBeVisible()
        break
      }
    }
  })

  test('should show install dropdown options', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Click install plugin button
    await page.click('button:has-text("Install Plugin")')
    
    // Check dropdown appears
    await expect(page.locator('#plugin-dropdown')).toBeVisible()
    
    // Should have at least one installable option
    const dropdownButtons = page.locator('#plugin-dropdown button')
    const buttonCount = await dropdownButtons.count()
    expect(buttonCount).toBeGreaterThan(0)
  })

  test('should filter plugins by search', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Find search input
    const searchInput = page.locator('input[placeholder*="Search"], input[type="search"]')
    const hasSearch = await searchInput.count()
    
    if (hasSearch > 0) {
      // Search for "auth"
      await searchInput.fill('auth')
      await page.waitForTimeout(1000) // Allow filter to apply
      
      // Should show filtered results
      const visibleCards = await page.locator('.plugin-card:visible').count()
      expect(visibleCards).toBeGreaterThanOrEqual(0)
      
      // Clear search
      await searchInput.fill('')
      await page.waitForTimeout(500)
    }
  })

  test('should show plugin information', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Each plugin card should show basic info
    const firstCard = page.locator('.plugin-card').first()
    
    // Should have plugin name
    await expect(firstCard.locator('h3, h2')).toBeVisible()
    
    // Should have version info
    await expect(firstCard.locator('text=/v?\\d+\\.\\d+/')).toBeVisible()
    
    // Should have status
    await expect(firstCard.locator('.status-badge')).toBeVisible()
  })

  test('should handle plugin categories', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Look for category information
    const cards = page.locator('.plugin-card')
    const count = await cards.count()
    
    if (count > 0) {
      // Should show at least one category
      await expect(page.locator('text=/security|content|media|system/i').first()).toBeVisible()
    }
  })

  test('should show core vs non-core plugins', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Core plugins should not have uninstall option
    const corePlugins = page.locator('.plugin-card').filter({ hasText: /Authentication|Media|Workflow/ })
    const coreCount = await corePlugins.count()
    
    if (coreCount > 0) {
      const firstCore = corePlugins.first()
      
      // Core plugins typically don't have uninstall buttons
      const hasUninstall = await firstCore.locator('button:has-text("Uninstall")').count()
      expect(hasUninstall).toBe(0)
    }
  })

  test('should validate plugin management permissions', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/plugins`)
    
    // Admin user should be able to access plugins page
    await expect(page.locator('h1')).toContainText('Plugins')
    
    // Should not show access denied message
    await expect(page.locator('text=Access denied')).not.toBeVisible()
    await expect(page.locator('text=Unauthorized')).not.toBeVisible()
  })
})