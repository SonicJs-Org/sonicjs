import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('New Content dropdown @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('shows dropdown button instead of plain link', async ({ page }) => {
    await page.goto('/admin/content')
    await expect(page.locator('#new-content-dropdown button')).toBeVisible()
    await expect(page.locator('#new-content-dropdown button')).toContainText('New Content')
  })

  test('dropdown is hidden by default', async ({ page }) => {
    await page.goto('/admin/content')
    await expect(page.locator('#new-content-menu')).toBeHidden()
  })

  test('dropdown opens on click and shows collection links', async ({ page }) => {
    await page.goto('/admin/content')
    await page.locator('#new-content-dropdown button').click()
    await expect(page.locator('#new-content-menu')).toBeVisible()
    // At least one collection link should appear
    const links = page.locator('#new-content-menu a')
    await expect(links.first()).toBeVisible()
  })

  test('collection links point to new content form', async ({ page }) => {
    await page.goto('/admin/content')
    await page.locator('#new-content-dropdown button').click()
    const firstLink = page.locator('#new-content-menu a').first()
    const href = await firstLink.getAttribute('href')
    expect(href).toMatch(/\/admin\/content\/new\?collection=/)
  })

  test('dropdown closes when clicking outside', async ({ page }) => {
    await page.goto('/admin/content')
    await page.locator('#new-content-dropdown button').click()
    await expect(page.locator('#new-content-menu')).toBeVisible()
    await page.locator('h1').click()
    await expect(page.locator('#new-content-menu')).toBeHidden()
  })
})
