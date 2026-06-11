import { test, expect, Page } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * Starter installs now seed ONLY the `admin` role. Every other role is
 * created and managed by an administrator, so these specs create the role
 * they need via the public Add-role form before asserting against it.
 */
async function ensureTestRole(page: Page, name: string, displayName: string): Promise<string> {
  const roleId = `role-${name}`
  await page.goto('/admin/rbac')
  await page.waitForLoadState('networkidle')
  await page.click('#subtab-roles-verbs')
  await page.locator('#panel-roles-verbs').waitFor({ state: 'visible' })
  const existing = page.locator(`input[name="display_name_${roleId}"]`)
  if ((await existing.count()) === 0) {
    await page.locator('form[action="/admin/rbac/roles"] input[name="name"]').fill(name)
    await page.locator('form[action="/admin/rbac/roles"] input[name="display_name"]').fill(displayName)
    await page.locator('form[action="/admin/rbac/roles"] button').filter({ hasText: 'Add role' }).click()
    await page.waitForLoadState('networkidle')
    await page.click('#subtab-roles-verbs')
    await page.locator('#panel-roles-verbs').waitFor({ state: 'visible' })
  }
  return roleId
}

test.describe('RBAC Roles & Verbs tab', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('navigates to Roles & Verbs tab via hash', async ({ page }) => {
    await page.goto('/admin/rbac#roles-verbs')
    await page.waitForLoadState('networkidle')
    const panel = page.locator('#panel-roles-verbs')
    await expect(panel).toBeVisible()
  })

  test('save roles persists display name change', async ({ page }) => {
    const roleId = await ensureTestRole(page, 'name-test', 'Name Test')

    const input = page.locator(`input[name="display_name_${roleId}"]`)
    await expect(input).toBeVisible()
    const original = await input.inputValue()

    const newName = 'Renamed Role'
    await input.fill(newName)

    await page.locator('button[type="submit"]').filter({ hasText: 'Save roles' }).click()
    await page.waitForLoadState('networkidle')

    const updatedInput = page.locator(`input[name="display_name_${roleId}"]`)
    await expect(updatedInput).toBeVisible()
    await expect(updatedInput).toHaveValue(newName)

    await updatedInput.fill(original)
    await page.locator('button[type="submit"]').filter({ hasText: 'Save roles' }).click()
    await page.waitForLoadState('networkidle')
    await expect(page.locator(`input[name="display_name_${roleId}"]`)).toHaveValue(original)
  })

  test('save roles persists portal access checkbox', async ({ page }) => {
    const roleId = await ensureTestRole(page, 'portal-test', 'Portal Test')

    const checkbox = page.locator(`input[name="portal_${roleId}"]`)
    await expect(checkbox).toBeVisible()
    const wasChecked = await checkbox.isChecked()

    await checkbox.click()
    const shouldBeChecked = !wasChecked

    await page.locator('button[type="submit"]').filter({ hasText: 'Save roles' }).click()
    await page.waitForLoadState('networkidle')

    const checkboxAfter = page.locator(`input[name="portal_${roleId}"]`)
    await expect(checkboxAfter).toBeVisible()
    if (shouldBeChecked) {
      await expect(checkboxAfter).toBeChecked()
    } else {
      await expect(checkboxAfter).not.toBeChecked()
    }

    if ((await checkboxAfter.isChecked()) !== wasChecked) {
      await checkboxAfter.click()
      await page.locator('button[type="submit"]').filter({ hasText: 'Save roles' }).click()
      await page.waitForLoadState('networkidle')
    }
  })

  test('add new role card is present below Roles & Verbs grid', async ({ page }) => {
    await page.goto('/admin/rbac#roles-verbs')
    await page.waitForLoadState('networkidle')

    const addRoleForm = page.locator('form[action="/admin/rbac/roles"]')
    await expect(addRoleForm).toBeVisible()

    await expect(addRoleForm.locator('input[name="name"]')).toBeVisible()
    await expect(addRoleForm.locator('input[name="display_name"]')).toBeVisible()

    const heading = page.locator('h3').filter({ hasText: 'Add new role' })
    await expect(heading).toBeVisible()
  })

  test('admin role is the only locked-and-undeletable system role', async ({ page }) => {
    await page.goto('/admin/rbac')
    await page.waitForLoadState('networkidle')
    await page.click('#subtab-roles-verbs')
    await page.locator('#panel-roles-verbs').waitFor({ state: 'visible' })

    // The admin row is system-marked (no editable slug) and has no delete button —
    // it is the only hardcoded role. Every other role on this page (if any) was
    // created by an administrator and is editable/deletable.
    const adminRow = page.locator('#roles-bulk-form li').filter({
      has: page.locator('input[name="display_name_role-admin"]'),
    })
    await expect(adminRow).toBeVisible()
    // System role: no editable name input, no delete button.
    await expect(adminRow.locator('input[name="name_role-admin"]')).toHaveCount(0)
    await expect(adminRow.locator('button', { hasText: 'delete' })).toHaveCount(0)
    // Admin portal checkbox is locked (cannot be unchecked — would cause lockout).
    await expect(adminRow.locator('input[name="portal_role-admin"]')).toBeDisabled()
  })
})
