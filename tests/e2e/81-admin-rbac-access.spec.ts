import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Admin RBAC access @smoke @auth', () => {
  test('admin user can access admin area without permission error', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/content')
    // Must NOT redirect to login with permission error
    await expect(page).not.toHaveURL(/error=You\+do\+not\+have\+permission/)
    await expect(page).not.toHaveURL(/\/auth\/login/)
    // Should be on the admin content page
    await expect(page).toHaveURL(/\/admin\/content/)
  })

  test('admin user can access admin dashboard', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin')
    await expect(page).not.toHaveURL(/error=You\+do\+not\+have\+permission/)
    await expect(page).not.toHaveURL(/\/auth\/login/)
  })
})
