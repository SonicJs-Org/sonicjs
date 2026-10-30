import { expect, test } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * `#content-form` is rendered with `novalidate` and validates server-side — see
 * `admin-content-form.template.ts` and the banner contract guarded by
 * `68-blog-post-validation-no-nesting.spec.ts`. So a required field left empty inside a group the
 * user collapsed must still be reported, and the failed submit must not navigate away or discard
 * the data the user did enter.
 *
 * Structured arrays ship an inert <template> holding a prototype item and Playwright's selector
 * engine looks inside template content, so item locators are anchored with `:scope >`.
 */
const ADD_MEMBER =
  ':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]'
const MEMBER_ITEM = ':scope > [data-structured-array-list] > .structured-array-item'

test.describe('Collapsible Validation Visibility @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/content/new?collection=e2e_test')
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await expect(page.locator('form#content-form')).toBeVisible()
  })

  test('should surface a validation error without navigating away or losing collapse state', async ({
    page,
  }) => {
    // Only structured-object groups are collapsible — `renderFieldGroup` is called with
    // collapsible=false for Basic Information / Content Details — so the required `title` lives in
    // a static group while `team` and `openingHoursWeek` are the ones the user can collapse.
    await page.fill('input[name="slug"]', `test-validation-visibility-${Date.now()}`)

    const collapsible = ['team', 'openingHoursWeek'].map((name) =>
      page.locator(`[data-structured-object][data-field-name="${name}"]`).first(),
    )
    for (const group of collapsible) {
      const content = group.locator(':scope > .field-group-content')
      if (!((await content.getAttribute('class')) || '').includes('hidden')) {
        await group.locator(':scope > .field-group-header').click()
      }
      await expect(content).toHaveClass(/hidden/)
    }

    // Title is required and has no fallback source, so leaving it empty is the error we want.
    await page.click('button[name="action"][value="save"]')

    const messages = page.locator('#form-messages')
    await expect(messages).toContainText('Please fix the validation errors below', {
      timeout: 10000,
    })
    await expect(messages).toContainText('title')

    // A rejected save must not navigate, must not drop what the user already typed, and must not
    // reset the collapse state (only #form-messages is swapped).
    expect(page.url()).toContain('/admin/content/new')
    await expect(page.locator('input[name="slug"]')).not.toHaveValue('')
    for (const group of collapsible) {
      await expect(group.locator(':scope > .field-group-content')).toHaveClass(/hidden/)
    }

    const titleField = page.locator('input[name="title"]')
    await expect(titleField).toBeVisible()
    await expect(titleField).toHaveValue('')
    await expect(titleField).toHaveAttribute('required', '')
  })

  test('should keep a collapsed nested repeater item editable after a rejected save', async ({
    page,
  }) => {
    await page.fill('input[name="slug"]', `test-validation-nested-${Date.now()}`)

    const teamGroup = page.locator('[data-structured-object][data-field-name="team"]').first()
    const teamContent = teamGroup.locator(':scope > .field-group-content')
    await expect(teamContent).toHaveClass(/hidden/)
    await teamGroup.locator(':scope > .field-group-header').click()
    await expect(teamContent).not.toHaveClass(/hidden/)

    const membersField = page
      .locator('[data-structured-array][data-field-name="team__members"]')
      .first()
    await membersField.locator(ADD_MEMBER).click()

    const firstMember = membersField.locator(MEMBER_ITEM).first()
    const firstMemberContent = firstMember.locator('[data-array-item-fields]').first()
    await expect(firstMemberContent).not.toHaveClass(/hidden/)
    await firstMember.locator('input[name$="__name"]').first().fill('Collapsed Member')

    // Collapse the item and its parent group, then submit with title still empty.
    await firstMember.locator('[data-action="toggle-item"]').first().click()
    await expect(firstMemberContent).toHaveClass(/hidden/)
    await teamGroup.locator(':scope > .field-group-header').click()
    await expect(teamContent).toHaveClass(/hidden/)

    await page.click('button[name="action"][value="save"]')
    await expect(page.locator('#form-messages')).toContainText(
      'Please fix the validation errors below',
      { timeout: 10000 },
    )

    // The nested item the user entered survives the rejected save and is still reachable.
    await teamGroup.locator(':scope > .field-group-header').click()
    await expect(teamContent).not.toHaveClass(/hidden/)
    await expect(membersField.locator(MEMBER_ITEM)).toHaveCount(1)
    await firstMember.locator('[data-action="toggle-item"]').first().click()
    await expect(firstMemberContent).not.toHaveClass(/hidden/)
    await expect(firstMember.locator('input[name$="__name"]').first()).toHaveValue(
      'Collapsed Member',
    )
  })
})
