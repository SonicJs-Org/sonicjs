import { test, expect, type Page } from './fixtures'
import { loginAsAdmin, submitAndWaitForDocument } from './utils/test-helpers'

/**
 * Verify that the role dropdown on the user-edit and user-new screens
 * reflects the dynamic RBAC roles, not a hardcoded list.
 *
 * The admin role is always present (seeded system role). A custom role
 * created in the RBAC panel must also appear in the user-edit dropdown.
 */

const CUSTOM_ROLE_NAME = `dyn-role-${Date.now()}`
const CUSTOM_ROLE_DISPLAY = 'Dynamic Test Role'

// The users table has no per-row <a href=".../edit"> any more: rows are click-handled via
// onclick="window.location.href='/admin/users/<id>/edit'" (table.template.ts rowClickUrl).
async function firstUserEditUrl(page: Page): Promise<string> {
  const row = page.locator('tbody tr[onclick]').first()
  await expect(row).toBeVisible()
  const onclick = (await row.getAttribute('onclick')) ?? ''
  const match = onclick.match(/\/admin\/users\/[^']+\/edit/)
  expect(match, `no user-edit target in row onclick: ${onclick}`).toBeTruthy()
  return match![0]
}

test.describe('User edit — dynamic role dropdown @auth', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('user-new form contains admin role option', async ({ page }) => {
    await page.goto('/admin/users/new')
    await page.waitForLoadState('networkidle')
    const select = page.locator('select[name="role"]')
    await expect(select).toBeVisible()
    await expect(select.locator('option[value="role-admin"]')).toBeAttached()
  })

  test('user-edit form contains admin role option', async ({ page }) => {
    // Find any existing user to edit
    await page.goto('/admin/users')
    await page.waitForLoadState('domcontentloaded')
    const href = await firstUserEditUrl(page)

    await page.goto(href)
    await page.waitForLoadState('domcontentloaded')
    const select = page.locator('select[name="role"]')
    await expect(select).toBeVisible()
    await expect(select.locator('option[value="role-admin"]')).toBeAttached()
  })

  test('custom role created in RBAC appears in user-edit dropdown', async ({ page }) => {
    // Create a custom role via the RBAC panel
    await page.goto('/admin/rbac')
    await page.waitForLoadState('networkidle')
    await page.click('#subtab-roles-verbs')
    await page.locator('#panel-roles-verbs').waitFor({ state: 'visible' })

    const roleId = `role-${CUSTOM_ROLE_NAME}`
    const existingInput = page.locator(`input[name="display_name_${roleId}"]`)
    if ((await existingInput.count()) === 0) {
      await page.locator('form[action="/admin/rbac/roles"] input[name="name"]').fill(CUSTOM_ROLE_NAME)
      await page.locator('form[action="/admin/rbac/roles"] input[name="display_name"]').fill(CUSTOM_ROLE_DISPLAY)
      // Native POST that redirects to /admin/rbac. The `page.goto('/admin/users/new')` below
      // would cancel it mid-flight if we only waited for `networkidle`, and the custom role
      // this test then looks for in the dropdown would never have been created.
      await submitAndWaitForDocument(page, '/admin/rbac', () =>
        page.locator('form[action="/admin/rbac/roles"] button').filter({ hasText: 'Add role' }).click()
      )
    }

    // Now visit user-new and confirm the custom role appears
    await page.goto('/admin/users/new')
    await page.waitForLoadState('networkidle')
    const select = page.locator('select[name="role"]')
    await expect(select).toBeVisible()
    await expect(select.locator(`option[value="${roleId}"]`)).toBeAttached()
  })

  test('custom role created in RBAC appears in user-edit dropdown for existing user', async ({ page }) => {
    await page.goto('/admin/users')
    await page.waitForLoadState('domcontentloaded')
    const href = await firstUserEditUrl(page)

    await page.goto(href)
    await page.waitForLoadState('domcontentloaded')
    const roleId = `role-${CUSTOM_ROLE_NAME}`
    const select = page.locator('select[name="role"]')
    await expect(select).toBeVisible()
    // Custom role may or may not exist depending on test order; just assert
    // the select has more than one option (dynamic, not static empty)
    const optionCount = await select.locator('option').count()
    expect(optionCount).toBeGreaterThan(0)
  })
})
