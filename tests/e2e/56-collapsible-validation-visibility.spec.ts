import { expect, test } from '@playwright/test'
import { ensureAdminUserExists, loginAsAdmin } from './utils/test-helpers'

test.describe('Collapsible Validation Visibility', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('should expand first collapsed error path and focus first invalid field on native invalid submit', async ({
    page,
  }) => {
    await page.goto('/admin/content/new')
    await page.waitForLoadState('networkidle', { timeout: 15000 })

    const pageBlocksLink = page
      .locator('a[href^="/admin/content/new?collection="]')
      .filter({ hasText: 'Page Blocks' })
      .first()
    await expect(pageBlocksLink).toBeVisible({ timeout: 10000 })
    await pageBlocksLink.click()
    await page.waitForLoadState('networkidle', { timeout: 15000 })

    await page.fill('input[name="title"]', `Test Validation Visibility ${Date.now()}`)
    await page.fill('input[name="slug"]', `test-validation-visibility-${Date.now()}`)

    const teamGroup = page.locator('[data-structured-object][data-field-name="team"]').first()
    const teamHeader = teamGroup.locator(':scope > .field-group-header')
    const teamContent = teamGroup.locator(':scope > .field-group-content')

    // Open once to add nested item, then collapse back to simulate hidden validation.
    await expect(teamContent).toHaveClass(/hidden/)
    await teamHeader.click()
    await expect(teamContent).not.toHaveClass(/hidden/)

    const membersField = page.locator('[data-structured-array][data-field-name="team__members"]').first()
    await membersField.locator('[data-action="add-item"]').click()

    const firstMember = membersField.locator('.structured-array-item').first()
    const firstMemberHeader = firstMember.locator('[data-action="toggle-item"]').first()
    const firstMemberContent = firstMember.locator('[data-array-item-fields]')
    await expect(firstMemberContent).not.toHaveClass(/hidden/)

    // Collapse nested item and parent group, leaving required Name empty.
    await firstMemberHeader.click()
    await expect(firstMemberContent).toHaveClass(/hidden/)
    await teamHeader.click()
    await expect(teamContent).toHaveClass(/hidden/)

    await page.click('button[name="action"][value="save_and_publish"]')

    // First invalid path should open automatically.
    await expect(teamContent).not.toHaveClass(/hidden/)
    await expect(firstMemberContent).not.toHaveClass(/hidden/)

    const focusedField = firstMember
      .locator('[data-array-item-fields] input[type="text"]:visible')
      .first()
    await expect(focusedField).toBeFocused()
  })
})
