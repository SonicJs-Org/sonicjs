import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  ensureAdminUserExists,
  ensureWorkflowTablesExist
} from './utils/test-helpers'

// Use environment variable for port or default to 8787
const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

test.describe('Plugin Filters and Search', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await ensureWorkflowTablesExist(page)
    await loginAsAdmin(page)
    await page.goto(`${BASE_URL}/admin/plugins`)
  })

  test('should have filter controls', async ({ page }) => {
    // Check for category filter
    const categoryFilter = page.locator('#category-filter')
    await expect(categoryFilter).toBeVisible()

    // Check for status filter
    const statusFilter = page.locator('#status-filter')
    await expect(statusFilter).toBeVisible()

    // Check for search input
    const searchInput = page.locator('#search-input')
    await expect(searchInput).toBeVisible()
  })

  test('should filter plugins by category', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await page.locator('.plugin-card').count()

    if (totalPlugins === 0) {
      console.log('No plugins to test filtering - skipping')
      return
    }

    // Select security category
    await page.selectOption('#category-filter', 'security')
    await page.waitForTimeout(500) // Allow filter to apply

    // Check that only security plugins are visible
    const visiblePlugins = await page.locator('.plugin-card:visible').count()

    // Should have fewer or equal plugins than total
    expect(visiblePlugins).toBeLessThanOrEqual(totalPlugins)

    // Verify all visible plugins have security category
    const visibleCards = await page.locator('.plugin-card:visible').all()
    for (const card of visibleCards) {
      const category = await card.getAttribute('data-category')
      expect(category).toBe('security')
    }

    // Reset filter
    await page.selectOption('#category-filter', '')
    await page.waitForTimeout(500)

    // Should show all plugins again
    const resetCount = await page.locator('.plugin-card:visible').count()
    expect(resetCount).toBe(totalPlugins)
  })

  test('should filter plugins by status', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await page.locator('.plugin-card').count()

    if (totalPlugins === 0) {
      console.log('No plugins to test filtering - skipping')
      return
    }

    // Select active status
    await page.selectOption('#status-filter', 'active')
    await page.waitForTimeout(500) // Allow filter to apply

    // Check that only active plugins are visible
    const visiblePlugins = await page.locator('.plugin-card:visible').count()

    // Should have fewer or equal plugins than total
    expect(visiblePlugins).toBeLessThanOrEqual(totalPlugins)

    // Verify all visible plugins have active status
    const visibleCards = await page.locator('.plugin-card:visible').all()
    for (const card of visibleCards) {
      const status = await card.getAttribute('data-status')
      expect(status).toBe('active')
    }

    // Try inactive status
    await page.selectOption('#status-filter', 'inactive')
    await page.waitForTimeout(500)

    const inactivePlugins = await page.locator('.plugin-card:visible').count()

    // Inactive count + active count should equal total (assuming no errors)
    // expect(visiblePlugins + inactivePlugins).toBeLessThanOrEqual(totalPlugins)

    // Reset filter
    await page.selectOption('#status-filter', '')
    await page.waitForTimeout(500)

    // Should show all plugins again
    const resetCount = await page.locator('.plugin-card:visible').count()
    expect(resetCount).toBe(totalPlugins)
  })

  test('should search plugins by name', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await page.locator('.plugin-card').count()

    if (totalPlugins === 0) {
      console.log('No plugins to test search - skipping')
      return
    }

    // Get first plugin name
    const firstCard = page.locator('.plugin-card').first()
    const firstPluginName = await firstCard.getAttribute('data-name')

    if (!firstPluginName) {
      console.log('No plugin name found - skipping')
      return
    }

    // Search for first few characters of the name
    const searchTerm = firstPluginName.substring(0, 4).toLowerCase()
    await page.fill('#search-input', searchTerm)
    await page.waitForTimeout(500) // Allow filter to apply

    // Should show filtered results
    const visiblePlugins = await page.locator('.plugin-card:visible').count()
    expect(visiblePlugins).toBeGreaterThan(0)
    expect(visiblePlugins).toBeLessThanOrEqual(totalPlugins)

    // All visible plugins should match search term
    const visibleCards = await page.locator('.plugin-card:visible').all()
    for (const card of visibleCards) {
      const name = await card.getAttribute('data-name')
      const description = await card.getAttribute('data-description')
      const matchesName = name?.toLowerCase().includes(searchTerm) || false
      const matchesDescription = description?.toLowerCase().includes(searchTerm) || false
      expect(matchesName || matchesDescription).toBe(true)
    }

    // Clear search
    await page.fill('#search-input', '')
    await page.waitForTimeout(500)

    // Should show all plugins again
    const resetCount = await page.locator('.plugin-card:visible').count()
    expect(resetCount).toBe(totalPlugins)
  })

  test('should search plugins by description', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await page.locator('.plugin-card').count()

    if (totalPlugins === 0) {
      console.log('No plugins to test search - skipping')
      return
    }

    // Search for common word that might be in descriptions
    await page.fill('#search-input', 'management')
    await page.waitForTimeout(500) // Allow filter to apply

    // Should show some results or none
    const visiblePlugins = await page.locator('.plugin-card:visible').count()
    expect(visiblePlugins).toBeGreaterThanOrEqual(0)
    expect(visiblePlugins).toBeLessThanOrEqual(totalPlugins)

    // Clear search
    await page.fill('#search-input', '')
    await page.waitForTimeout(500)
  })

  test('should combine category and status filters', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await page.locator('.plugin-card').count()

    if (totalPlugins === 0) {
      console.log('No plugins to test filtering - skipping')
      return
    }

    // Select security category AND active status
    await page.selectOption('#category-filter', 'security')
    await page.selectOption('#status-filter', 'active')
    await page.waitForTimeout(500) // Allow filter to apply

    // Should show filtered results
    const visiblePlugins = await page.locator('.plugin-card:visible').count()
    expect(visiblePlugins).toBeLessThanOrEqual(totalPlugins)

    // Verify all visible plugins match both filters
    const visibleCards = await page.locator('.plugin-card:visible').all()
    for (const card of visibleCards) {
      const category = await card.getAttribute('data-category')
      const status = await card.getAttribute('data-status')
      expect(category).toBe('security')
      expect(status).toBe('active')
    }

    // Reset filters
    await page.selectOption('#category-filter', '')
    await page.selectOption('#status-filter', '')
    await page.waitForTimeout(500)
  })

  test('should combine all three filters', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await page.locator('.plugin-card').count()

    if (totalPlugins === 0) {
      console.log('No plugins to test filtering - skipping')
      return
    }

    // Apply all three filters
    await page.selectOption('#category-filter', 'security')
    await page.selectOption('#status-filter', 'active')
    await page.fill('#search-input', 'auth')
    await page.waitForTimeout(500) // Allow filter to apply

    // Should show highly filtered results (possibly zero)
    const visiblePlugins = await page.locator('.plugin-card:visible').count()
    expect(visiblePlugins).toBeGreaterThanOrEqual(0)
    expect(visiblePlugins).toBeLessThanOrEqual(totalPlugins)

    // If any plugins visible, verify they match all filters
    if (visiblePlugins > 0) {
      const visibleCards = await page.locator('.plugin-card:visible').all()
      for (const card of visibleCards) {
        const category = await card.getAttribute('data-category')
        const status = await card.getAttribute('data-status')
        const name = await card.getAttribute('data-name')
        const description = await card.getAttribute('data-description')

        expect(category).toBe('security')
        expect(status).toBe('active')

        const matchesSearch =
          name?.toLowerCase().includes('auth') ||
          description?.toLowerCase().includes('auth')
        expect(matchesSearch).toBe(true)
      }
    }

    // Reset all filters
    await page.selectOption('#category-filter', '')
    await page.selectOption('#status-filter', '')
    await page.fill('#search-input', '')
    await page.waitForTimeout(500)
  })

  test('should show no results message when no plugins match', async ({ page }) => {
    // Get total plugin count
    const totalPlugins = await page.locator('.plugin-card').count()

    if (totalPlugins === 0) {
      console.log('No plugins to test - skipping')
      return
    }

    // Search for something that definitely won't match
    await page.fill('#search-input', 'xyzabc123nonexistent')
    await page.waitForTimeout(500) // Allow filter to apply

    // Should show no plugins
    const visiblePlugins = await page.locator('.plugin-card:visible').count()
    expect(visiblePlugins).toBe(0)

    // Should show "no results" message
    const noResultsMsg = page.locator('#no-results-message')
    await expect(noResultsMsg).toBeVisible()
    await expect(noResultsMsg).toContainText('No plugins found')

    // Clear search
    await page.fill('#search-input', '')
    await page.waitForTimeout(500)

    // No results message should be hidden
    await expect(noResultsMsg).not.toBeVisible()

    // Plugins should be visible again
    const resetCount = await page.locator('.plugin-card:visible').count()
    expect(resetCount).toBe(totalPlugins)
  })

  test('should maintain filter state when toggling plugin status', async ({ page }) => {
    // Apply a filter first
    await page.selectOption('#category-filter', 'security')
    await page.waitForTimeout(500)

    const initialCount = await page.locator('.plugin-card:visible').count()

    if (initialCount === 0) {
      console.log('No security plugins - skipping')
      return
    }

    // Try to toggle a plugin
    const firstCard = page.locator('.plugin-card:visible').first()
    const activateBtn = firstCard.locator('button:has-text("Activate")')
    const deactivateBtn = firstCard.locator('button:has-text("Deactivate")')

    const hasActivate = await activateBtn.count()
    const hasDeactivate = await deactivateBtn.count()

    if (hasActivate > 0) {
      await activateBtn.click()
      await page.waitForTimeout(1000)
    } else if (hasDeactivate > 0) {
      await deactivateBtn.click()
      await page.waitForTimeout(1000)
    }

    // Verify category filter is still applied
    const selectedCategory = await page.locator('#category-filter').inputValue()
    expect(selectedCategory).toBe('security')

    // Reset filter
    await page.selectOption('#category-filter', '')
    await page.waitForTimeout(500)
  })

  test('should have correct category options', async ({ page }) => {
    const categoryFilter = page.locator('#category-filter')

    // Check that all expected category options exist
    const options = await categoryFilter.locator('option').allTextContents()

    expect(options).toContain('All Categories')
    expect(options).toContain('Content Management')
    expect(options).toContain('Media')
    expect(options).toContain('SEO & Analytics')
    expect(options).toContain('Security')
    expect(options).toContain('Utilities')
    expect(options).toContain('System')
    expect(options).toContain('Development')
  })

  test('should have correct status options', async ({ page }) => {
    const statusFilter = page.locator('#status-filter')

    // Check that all expected status options exist
    const options = await statusFilter.locator('option').allTextContents()

    expect(options).toContain('All Status')
    expect(options).toContain('Active')
    expect(options).toContain('Inactive')
    expect(options).toContain('Error')
  })
})
