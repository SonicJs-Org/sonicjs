import { expect, test, type Page } from '@playwright/test'
import { ensureAdminUserExists, loginAsAdmin } from './utils/test-helpers'

async function resolvePageBlocksCollectionKey(page: Page): Promise<string> {
  await page.goto('/admin/content/new')
  await page.waitForLoadState('networkidle', { timeout: 15000 })

  const pageBlocksLink = page
    .locator('a[href^="/admin/content/new?collection="]')
    .filter({ hasText: 'Page Blocks' })
    .first()

  await expect(pageBlocksLink).toBeVisible({ timeout: 10000 })
  const href = await pageBlocksLink.getAttribute('href')
  const match = href?.match(/[?&]collection=([^&]+)/)
  return match?.[1] || 'page_blocks'
}

async function gotoPageBlocksNewForm(page: Page) {
  const collectionKey = await resolvePageBlocksCollectionKey(page)
  await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey))
  await page.waitForLoadState('networkidle', { timeout: 15000 })
  const titleField = page.locator('input[name="title"]').first()
  if (await titleField.count()) {
    await expect(titleField).toBeVisible({ timeout: 10000 })
    return collectionKey
  }

  const pageBlocksLink = page
    .locator('a[href^="/admin/content/new?collection="]')
    .filter({ hasText: 'Page Blocks' })
    .first()
  if (await pageBlocksLink.count()) {
    await pageBlocksLink.click()
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await expect(page.locator('input[name="title"]').first()).toBeVisible({ timeout: 10000 })
    return collectionKey
  }

  await expect(page.locator('form#content-form')).toBeVisible({ timeout: 10000 })
  return collectionKey
}

async function saveAndCaptureEditUrl(page: Page): Promise<string> {
  await page.click('button[name="action"][value="save_and_publish"]')
  await page.waitForLoadState('networkidle', { timeout: 15000 })
  const currentUrl = page.url()
  if (/\/admin\/content\/[^/]+\/edit/.test(currentUrl)) {
    return currentUrl
  }

  // Fallback for environments that may not auto-redirect after save.
  const editLink = page.locator('a[href*="/admin/content/"][href*="/edit"]').first()
  await expect(editLink).toBeVisible({ timeout: 10000 })
  const href = await editLink.getAttribute('href')
  if (!href) {
    throw new Error('Could not resolve edit URL after saving content')
  }
  await page.goto(href)
  await page.waitForLoadState('networkidle', { timeout: 15000 })
  await expect(page.locator('form#content-form')).toBeVisible()
  return page.url()
}

test.describe('Collapsible State Persistence', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('should persist object/repeater/block collapsed state per document in session', async ({
    page,
  }) => {
    const docATitle = `Test Collapse State A ${Date.now()}`
    const docASlug = `test-collapse-state-a-${Date.now()}`
    const docBTitle = `Test Collapse State B ${Date.now()}`
    const docBSlug = `test-collapse-state-b-${Date.now()}`

    const collectionKey = await resolvePageBlocksCollectionKey(page)

    // Create document A with blocks and repeater items.
    await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey))
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    const formTitle = page.locator('input[name="title"]').first()
    if (!(await formTitle.count())) {
      await gotoPageBlocksNewForm(page)
    }
    await page.fill('input[name="title"]', docATitle)
    await page.fill('input[name="slug"]', docASlug)

    const teamGroup = page.locator('[data-structured-object][data-field-name="team"]').first()
    const teamContent = teamGroup.locator(':scope > .field-group-content')
    await expect(teamContent).toHaveClass(/hidden/)
    await teamGroup.locator(':scope > .field-group-header').click()
    await expect(teamContent).not.toHaveClass(/hidden/)

    const membersField = page.locator('[data-structured-array][data-field-name="team__members"]').first()
    await expect(membersField).toBeVisible()
    await membersField.locator('[data-action="add-item"]').click()
    await membersField.locator('[data-action="add-item"]').click()

    const memberItems = membersField.locator('.structured-array-item')
    await expect(memberItems).toHaveCount(2)
    await expect(memberItems.nth(0).locator('[data-array-item-fields]')).not.toHaveClass(/hidden/)
    await expect(memberItems.nth(1).locator('[data-array-item-fields]')).not.toHaveClass(/hidden/)
    await memberItems.nth(0).locator('input[type="text"]').first().fill('Member One')
    await memberItems.nth(1).locator('input[type="text"]').first().fill('Member Two')
    await memberItems.nth(0).locator('[data-action="toggle-item"]').first().click()
    await expect(memberItems.nth(0).locator('[data-array-item-fields]')).toHaveClass(/hidden/)
    await expect(memberItems.nth(1).locator('[data-array-item-fields]')).not.toHaveClass(/hidden/)

    const blocksField = page.locator('[data-field-name="body"]')
    await expect(blocksField).toBeVisible()
    await blocksField.locator('[data-role="block-type-select"]').selectOption('hero')
    await blocksField.locator('[data-action="add-block"]').click()
    await blocksField.locator('[data-role="block-type-select"]').selectOption('text')
    await blocksField.locator('[data-action="add-block"]').click()

    const blockItems = blocksField.locator('.blocks-item')
    await expect(blockItems).toHaveCount(2)
    await expect(blockItems.nth(0).locator('[data-block-content]')).not.toHaveClass(/hidden/)
    await expect(blockItems.nth(1).locator('[data-block-content]')).not.toHaveClass(/hidden/)
    await blockItems.nth(0).locator('input[type="text"]').first().fill('Hero Heading')
    await blockItems.nth(1).locator('input[type="text"]').first().fill('Text Heading')
    await blockItems.nth(1).locator('textarea').first().fill('Text body content')

    const docAEditUrl = await saveAndCaptureEditUrl(page)

    // Set UI collapse state on the saved edit page (same document path/key).
    await page.goto(docAEditUrl)
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await expect(page.locator('form#content-form')).toBeVisible()

    const editTeamGroup = page.locator('[data-structured-object][data-field-name="team"]').first()
    const editTeamContent = editTeamGroup.locator(':scope > .field-group-content')
    await expect(editTeamContent).toHaveClass(/hidden/)
    await editTeamGroup.locator(':scope > .field-group-header').click()
    await expect(editTeamContent).not.toHaveClass(/hidden/)

    const editMembersField = page
      .locator('[data-structured-array][data-field-name="team__members"]')
      .first()
    const editMemberItems = editMembersField.locator('.structured-array-item')
    await expect(editMemberItems).toHaveCount(2)
    await expect(editMemberItems.nth(0).locator('[data-array-item-fields]')).toHaveClass(/hidden/)
    await expect(editMemberItems.nth(1).locator('[data-array-item-fields]')).toHaveClass(/hidden/)
    await editMemberItems.nth(1).locator('[data-action="toggle-item"]').first().click()
    await expect(editMemberItems.nth(1).locator('[data-array-item-fields]')).not.toHaveClass(/hidden/)

    const editBlocksField = page.locator('[data-field-name="body"]')
    const editBlockItems = editBlocksField.locator('.blocks-item')
    await expect(editBlockItems).toHaveCount(2)
    await expect(editBlockItems.nth(0).locator('[data-block-content]')).toHaveClass(/hidden/)
    await expect(editBlockItems.nth(1).locator('[data-block-content]')).toHaveClass(/hidden/)
    await editBlockItems.nth(1).locator('[data-action="toggle-block"]').first().click()
    await expect(editBlockItems.nth(1).locator('[data-block-content]')).not.toHaveClass(/hidden/)
    await expect(editBlockItems.nth(0).locator('[data-block-content]')).toHaveClass(/hidden/)
    await expect(editBlockItems.nth(1).locator('[data-block-content]')).not.toHaveClass(/hidden/)

    // Create document B without toggling grouped fields so defaults are used.
    await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey))
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    const formTitleB = page.locator('input[name="title"]').first()
    if (!(await formTitleB.count())) {
      await gotoPageBlocksNewForm(page)
    }
    await page.fill('input[name="title"]', docBTitle)
    await page.fill('input[name="slug"]', docBSlug)
    const docBEditUrl = await saveAndCaptureEditUrl(page)

    // Return to document A and verify state restoration.
    await page.goto(docAEditUrl)
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await expect(page.locator('form#content-form')).toBeVisible()
    const restoredTeamGroup = page
      .locator('[data-structured-object][data-field-name="team"]')
      .first()
    const restoredTeamContent = restoredTeamGroup.locator(':scope > .field-group-content')
    await expect(restoredTeamContent).not.toHaveClass(/hidden/)

    const restoredMembers = page
      .locator('[data-structured-array][data-field-name="team__members"] .structured-array-item')
    await expect(restoredMembers).toHaveCount(2)
    await expect(restoredMembers.nth(0).locator('[data-array-item-fields]')).toHaveClass(/hidden/)
    await expect(restoredMembers.nth(1).locator('[data-array-item-fields]')).not.toHaveClass(/hidden/)

    const restoredBlocks = page.locator('[data-field-name="body"] .blocks-item')
    await expect(restoredBlocks).toHaveCount(2)
    await expect(restoredBlocks.nth(0).locator('[data-block-content]')).toHaveClass(/hidden/)
    await expect(restoredBlocks.nth(1).locator('[data-block-content]')).not.toHaveClass(/hidden/)

    // Reorder should keep each item's expanded/collapsed state.
    await restoredMembers.nth(0).locator('[data-action="move-down"]').click()
    await expect(restoredMembers.nth(0).locator('[data-array-item-fields]')).not.toHaveClass(/hidden/)
    await expect(restoredMembers.nth(1).locator('[data-array-item-fields]')).toHaveClass(/hidden/)

    await restoredBlocks.nth(0).locator('[data-action="move-down"]').click()
    await expect(restoredBlocks.nth(0).locator('[data-block-content]')).not.toHaveClass(/hidden/)
    await expect(restoredBlocks.nth(1).locator('[data-block-content]')).toHaveClass(/hidden/)

    // Open different document and confirm defaults still apply there.
    await page.goto(docBEditUrl)
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await expect(page.locator('form#content-form')).toBeVisible()
    const docBTeamGroup = page
      .locator('[data-structured-object][data-field-name="team"]')
      .first()
    await expect(docBTeamGroup.locator(':scope > .field-group-content')).toHaveClass(/hidden/)
  })
})
