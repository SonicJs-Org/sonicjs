import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Admin Panel naming and seeded roles @auth', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('Roles & Verbs tab shows "Admin Panel" label (not "Access portal")', async ({ page }) => {
    await page.goto('/admin/rbac')
    // Navigate to Roles & Verbs tab where the Admin Panel checkbox lives
    await page.click('text=Roles & Verbs')
    await page.waitForSelector('text=Roles')
    const body = await page.locator('body').innerText()
    // "Admin Panel" must appear (the checkbox label)
    expect(body).toContain('Admin Panel')
    // "Access portal" must not appear anywhere
    expect(body).not.toContain('Access portal')
  })

  test('seeded roles include Administrator, Editor, Authenticated, Public', async ({ page }) => {
    await page.goto('/admin/rbac')
    // Navigate to Roles & Verbs tab where all seeded roles are listed
    await page.click('text=Roles & Verbs')
    await page.waitForSelector('text=Roles')

    // Display names are editable inputs in the bulk-rename form, so they live in `value`,
    // not in the page's text content — innerText would never see them.
    const displayNames = page.locator('#roles-bulk-form input[name^="display_name_"]')
    await expect(displayNames.first()).toBeVisible()
    const names = await displayNames.evaluateAll((els) =>
      els.map((el) => (el as HTMLInputElement).value),
    )

    expect(names).toContain('Administrator')
    expect(names).toContain('Editor')
    expect(names).toContain('Authenticated')
    expect(names).toContain('Public')
  })
})
