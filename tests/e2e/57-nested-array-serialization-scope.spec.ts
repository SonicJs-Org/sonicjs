import { expect, test, type Locator, type Page } from './fixtures'
import { ensureAdminUserExists, loginAsAdmin } from './utils/test-helpers'

async function resolvePageBlocksCollectionKey(page: Page): Promise<string> {
  await page.goto('/admin/content/new')
  await page.waitForLoadState('networkidle', { timeout: 15000 })

  const e2eTestLink = page
    .locator('a[href^="/admin/content/new?collection="]')
    .filter({ hasText: 'E2E Test' })
    .first()

  await expect(e2eTestLink).toBeVisible({ timeout: 10000 })
  const href = await e2eTestLink.getAttribute('href')
  const match = href?.match(/[?&]collection=([^&]+)/)
  return match?.[1] || 'e2e_test'
}

async function gotoWithRetry(page: Page, url: string): Promise<void> {
  try {
    await page.goto(url)
  } catch (error) {
    const message = String(error)
    if (!message.includes('net::ERR_ABORTED')) {
      throw error
    }
    await page.waitForTimeout(300)
    await page.goto(url)
  }
}

async function addRootMemberAndWaitForCount(
  membersField: Locator,
  topLevelMembers: Locator,
  expectedCount: number,
) {
  await expect(membersField).toHaveAttribute('data-structured-initialized', 'true')

  const addButton = membersField
    .locator(':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]')
    .first()
  await expect(addButton).toBeVisible()

  for (let attempt = 0; attempt < 3; attempt++) {
    await addButton.click()
    try {
      await expect(topLevelMembers).toHaveCount(expectedCount, { timeout: 2000 })
      return
    } catch {
      // Fallback to DOM click in case pointer interactions are intercepted while page settles.
      await addButton.evaluate((button) => {
        if (button instanceof HTMLButtonElement) {
          button.click()
        }
      })
      try {
        await expect(topLevelMembers).toHaveCount(expectedCount, { timeout: 2000 })
        return
      } catch {
        // Retry click if client listeners or async init are still settling on edit reload.
      }
    }
  }

  await expect(topLevelMembers).toHaveCount(expectedCount)
}

async function confirmRepeaterDelete(page: Page) {
  const dialog = page.locator('#delete-repeater-item-confirm')
  await expect(dialog).toHaveJSProperty('open', true)
  // Wait for real entrance animations, then perform the side effect exactly once.
  // Re-clicking inside toPass can hide a broken dialog lifecycle or replay a deletion.
  await dialog.evaluate(async element => {
    await Promise.all(element.getAnimations({ subtree: true }).map(animation => animation.finished))
  })
  await dialog.locator('.confirm-button').click()
  await expect(dialog).toHaveJSProperty('open', false)
}

/**
 * Structured arrays ship an inert <template> holding a prototype item, and Playwright's selector
 * engine looks inside template content. Item/control locators are therefore anchored with
 * `:scope >` so they cannot match the prototype — an unanchored `.structured-array-item` counts
 * the template copy too (that is what made the post-remove `toHaveCount(0)` see 1).
 */
test.describe('Nested Array Serialization Scope @content', () => {
  const getEditUrlFromPage = async (page: Page): Promise<string | null> => {
    const editMatch = page.url().match(/\/admin\/content\/([^/]+)\/edit/)
    if (editMatch?.[1]) {
      return page.url()
    }

    const editLink = page.locator('a[href*="/admin/content/"][href*="/edit"]').first()
    if (!(await editLink.isVisible({ timeout: 5000 }).catch(() => false))) {
      return null
    }
    const href = await editLink.getAttribute('href')
    return href || null
  }

  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('should serialize only top-level repeater items and keep children nested', async ({ page }) => {
    let createdContentId: string | null = null
    const title = `Nested Array Scope ${Date.now()}`
    const slug = `nested-array-scope-${Date.now()}`

    const collectionKey = await resolvePageBlocksCollectionKey(page)
    await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey))
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await expect(page.locator('form#content-form')).toBeVisible({ timeout: 10000 })

    await page.fill('input[name="title"]', title)
    await page.fill('input[name="slug"]', slug)

    const teamGroup = page.locator('[data-structured-object][data-field-name="team"]').first()
    const teamContent = teamGroup.locator(':scope > .field-group-content')
    if ((await teamContent.getAttribute('class'))?.includes('hidden')) {
      await teamGroup.locator(':scope > .field-group-header').click()
      await expect(teamContent).not.toHaveClass(/hidden/)
    }

    const membersField = page.locator('[data-structured-array][data-field-name="team__members"]').first()
    const topLevelMembers = membersField.locator(':scope > [data-structured-array-list] > .structured-array-item')
    await expect(membersField).toBeVisible()
    await membersField
      .locator(':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]')
      .click()

    const firstMember = topLevelMembers.first()
    await expect(firstMember).toBeVisible()
    await firstMember.locator('input[name$="__name"]').first().fill('Parent Member')

    const childrenField = firstMember
      .locator('[data-structured-array][data-field-name$="__children"]')
      .first()
    await expect(childrenField).toBeVisible()
    await childrenField.locator(':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]').click()

    const firstChild = childrenField.locator(':scope > [data-structured-array-list] > .structured-array-item').first()
    await expect(firstChild).toBeVisible()
    const firstChildFields = firstChild.locator('[data-array-item-fields]').first()
    if ((await firstChildFields.getAttribute('class'))?.includes('hidden')) {
      await firstChild.locator('[data-action="toggle-item"]').first().click()
      await expect(firstChildFields).not.toHaveClass(/hidden/)
    }
    await firstChild.locator('input[name$="__name"]').first().fill('Nested Child')
    await childrenField.locator(':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]').click()

    const secondChild = childrenField.locator(':scope > [data-structured-array-list] > .structured-array-item').nth(1)
    await expect(secondChild).toBeVisible()
    const secondChildFields = secondChild.locator('[data-array-item-fields]').first()
    if ((await secondChildFields.getAttribute('class'))?.includes('hidden')) {
      await secondChild.locator('[data-action="toggle-item"]').first().click()
      await expect(secondChildFields).not.toHaveClass(/hidden/)
    }
    await secondChild.locator('input[name$="__name"]').first().fill('Nested Child 2')
    await expect(topLevelMembers).toHaveCount(1)

    await membersField
      .locator(':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]')
      .click()
    await expect(topLevelMembers).toHaveCount(2)
    const secondMember = topLevelMembers.nth(1)
    await secondMember.locator('input[name$="__name"]').first().fill('Second Parent')
    const secondMemberChildrenField = secondMember
      .locator('[data-structured-array][data-field-name$="__children"]')
      .first()
    await expect(secondMemberChildrenField).toBeVisible()
    await secondMemberChildrenField.locator(':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]').click()
    const secondMemberFirstChild = secondMemberChildrenField.locator(':scope > [data-structured-array-list] > .structured-array-item').first()
    await expect(secondMemberFirstChild).toBeVisible()
    const secondMemberFirstChildFields = secondMemberFirstChild.locator('[data-array-item-fields]').first()
    if ((await secondMemberFirstChildFields.getAttribute('class'))?.includes('hidden')) {
      await secondMemberFirstChild.locator('[data-action="toggle-item"]').first().click()
      await expect(secondMemberFirstChildFields).not.toHaveClass(/hidden/)
    }
    await secondMemberFirstChild.locator('input[name$="__name"]').first().fill('Second Parent Child')
    await expect(topLevelMembers).toHaveCount(2)

    await membersField
      .locator(':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]')
      .click()
    await expect(topLevelMembers).toHaveCount(3)
    const thirdMember = topLevelMembers.nth(2)
    await thirdMember.locator('input[name$="__name"]').first().fill('Third Parent')
    const thirdMemberChildrenField = thirdMember
      .locator('[data-structured-array][data-field-name$="__children"]')
      .first()
    await expect(thirdMemberChildrenField).toBeVisible()
    await thirdMemberChildrenField.locator(':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]').click()
    const thirdMemberFirstChild = thirdMemberChildrenField.locator(':scope > [data-structured-array-list] > .structured-array-item').first()
    await expect(thirdMemberFirstChild).toBeVisible()
    const thirdMemberFirstChildFields = thirdMemberFirstChild.locator('[data-array-item-fields]').first()
    if ((await thirdMemberFirstChildFields.getAttribute('class'))?.includes('hidden')) {
      await thirdMemberFirstChild.locator('[data-action="toggle-item"]').first().click()
      await expect(thirdMemberFirstChildFields).not.toHaveClass(/hidden/)
    }
    await thirdMemberFirstChild.locator('input[name$="__name"]').first().fill('Third Parent Child')
    await expect(topLevelMembers).toHaveCount(3)

    await page.click('button[name="action"][value="save"]')
    // A new-document save answers the HTMX request with `HX-Redirect: /admin/content/<id>/edit`,
    // and htmx sets location *after* that response — networkidle can therefore resolve while the
    // URL is still /admin/content/new. Wait for the edit URL instead of racing it.
    await page.waitForURL(/\/admin\/content\/[^/]+\/edit/, { timeout: 15000 })
    await page.waitForLoadState('networkidle', { timeout: 15000 })

    const editMatch = page.url().match(/\/admin\/content\/([^/]+)\/edit/)
    if (editMatch?.[1]) {
      createdContentId = editMatch[1]
    } else {
      const editLink = page.locator('a[href*="/admin/content/"][href*="/edit"]').first()
      await expect(editLink).toBeVisible({ timeout: 10000 })
      const href = await editLink.getAttribute('href')
      const hrefMatch = href?.match(/\/admin\/content\/([^/]+)\/edit/)
      createdContentId = hrefMatch?.[1] || null
      if (href) {
        await page.goto(href)
        await page.waitForLoadState('networkidle', { timeout: 15000 })
      }
    }

    const teamRaw = await page.locator('input[name="team"]').inputValue()
    const team = JSON.parse(teamRaw)

    expect(Array.isArray(team.members)).toBe(true)
    expect(team.members).toHaveLength(3)
    expect(team.members[0]?.name).toBe('Parent Member')
    expect(Array.isArray(team.members[0]?.children)).toBe(true)
    expect(team.members[0].children).toHaveLength(2)
    expect(team.members[0].children[0]?.name).toBe('Nested Child')
    expect(team.members[0].children[1]?.name).toBe('Nested Child 2')
    expect(team.members[1]?.name).toBe('Second Parent')
    expect(Array.isArray(team.members[1]?.children)).toBe(true)
    expect(team.members[1].children).toHaveLength(1)
    expect(team.members[1].children[0]?.name).toBe('Second Parent Child')
    expect(team.members[2]?.name).toBe('Third Parent')
    expect(Array.isArray(team.members[2]?.children)).toBe(true)
    expect(team.members[2].children).toHaveLength(1)
    expect(team.members[2].children[0]?.name).toBe('Third Parent Child')

    if (createdContentId) {
      const deleteResponse = await page.request.delete(`/admin/content/${createdContentId}`)
      expect(deleteResponse.ok()).toBeTruthy()
    }
  })

  test('should persist nested child deletion after save and reload', async ({ page }) => {
    let createdContentId: string | null = null
    const title = `Nested Array Delete ${Date.now()}`
    const slug = `nested-array-delete-${Date.now()}`

    const collectionKey = await resolvePageBlocksCollectionKey(page)
    await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey))
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await expect(page.locator('form#content-form')).toBeVisible({ timeout: 10000 })

    await page.fill('input[name="title"]', title)
    await page.fill('input[name="slug"]', slug)

    const teamGroup = page.locator('[data-structured-object][data-field-name="team"]').first()
    const teamContent = teamGroup.locator(':scope > .field-group-content')
    if ((await teamContent.getAttribute('class'))?.includes('hidden')) {
      await teamGroup.locator(':scope > .field-group-header').click()
      await expect(teamContent).not.toHaveClass(/hidden/)
    }

    const membersField = page.locator('[data-structured-array][data-field-name="team__members"]').first()
    const topLevelMembers = membersField.locator(':scope > [data-structured-array-list] > .structured-array-item')
    await expect(membersField).toBeVisible()
    await membersField
      .locator(':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]')
      .click()

    const firstMember = topLevelMembers.first()
    await expect(firstMember).toBeVisible()
    await firstMember.locator('input[name$="__name"]').first().fill('Parent Member')

    const childrenField = firstMember
      .locator('[data-structured-array][data-field-name$="__children"]')
      .first()
    await expect(childrenField).toBeVisible()
    await childrenField.locator(':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]').click()
    const firstChild = childrenField.locator(':scope > [data-structured-array-list] > .structured-array-item').first()
    await expect(firstChild).toBeVisible()

    // Removing a repeater item opens the shared confirmation dialog (requestRepeaterDelete →
    // showConfirmDialog('delete-repeater-item-confirm')); the item is only detached on confirm.
    // Require the custom-element lifecycle before opening. This is readiness only;
    // the subsequent one-click close assertion must still catch lifecycle regressions.
    await expect(page.locator('el-dialog:defined > #delete-repeater-item-confirm')).toHaveCount(1)
    await firstChild.locator('[data-action="remove-item"]').first().click()
    await confirmRepeaterDelete(page)
    await expect(childrenField.locator(':scope > [data-structured-array-list] > .structured-array-item')).toHaveCount(0)

    await page.click('button[name="action"][value="save"]')
    // A new-document save answers the HTMX request with `HX-Redirect: /admin/content/<id>/edit`,
    // and htmx sets location *after* that response — networkidle can therefore resolve while the
    // URL is still /admin/content/new. Wait for the edit URL instead of racing it.
    await page.waitForURL(/\/admin\/content\/[^/]+\/edit/, { timeout: 15000 })
    await page.waitForLoadState('networkidle', { timeout: 15000 })

    const editMatch = page.url().match(/\/admin\/content\/([^/]+)\/edit/)
    if (editMatch?.[1]) {
      createdContentId = editMatch[1]
    } else {
      const editLink = page.locator('a[href*="/admin/content/"][href*="/edit"]').first()
      await expect(editLink).toBeVisible({ timeout: 10000 })
      const href = await editLink.getAttribute('href')
      const hrefMatch = href?.match(/\/admin\/content\/([^/]+)\/edit/)
      createdContentId = hrefMatch?.[1] || null
      if (href) {
        await page.goto(href)
        await page.waitForLoadState('networkidle', { timeout: 15000 })
      }
    }

    const teamRaw = await page.locator('input[name="team"]').inputValue()
    const team = JSON.parse(teamRaw)
    expect(Array.isArray(team.members)).toBe(true)
    expect(team.members).toHaveLength(1)
    expect(Array.isArray(team.members[0]?.children)).toBe(true)
    expect(team.members[0].children).toHaveLength(0)

    if (createdContentId) {
      const deleteResponse = await page.request.delete(`/admin/content/${createdContentId}`)
      expect(deleteResponse.ok()).toBeTruthy()
    }
  })

  test('should allow adding nested child on newly added root item after save and return', async ({ page }) => {
    let createdContentId: string | null = null
    const title = `Nested Array Return ${Date.now()}`
    const slug = `nested-array-return-${Date.now()}`

    const collectionKey = await resolvePageBlocksCollectionKey(page)
    await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey))
    await page.waitForLoadState('networkidle', { timeout: 15000 })
    await expect(page.locator('form#content-form')).toBeVisible({ timeout: 10000 })

    await page.fill('input[name="title"]', title)
    await page.fill('input[name="slug"]', slug)

    const teamGroup = page.locator('[data-structured-object][data-field-name="team"]').first()
    const teamContent = teamGroup.locator(':scope > .field-group-content')
    if ((await teamContent.getAttribute('class'))?.includes('hidden')) {
      await teamGroup.locator(':scope > .field-group-header').click()
      await expect(teamContent).not.toHaveClass(/hidden/)
    }

    const membersField = page.locator('[data-structured-array][data-field-name="team__members"]').first()
    const topLevelMembers = membersField.locator(':scope > [data-structured-array-list] > .structured-array-item')
    await expect(membersField).toBeVisible()
    await addRootMemberAndWaitForCount(membersField, topLevelMembers, 1)
    await expect(topLevelMembers).toHaveCount(1)
    await topLevelMembers.nth(0).locator('input[name$="__name"]').first().fill('Initial Parent')

    await page.click('button[name="action"][value="save"]')
    // A new-document save answers the HTMX request with `HX-Redirect: /admin/content/<id>/edit`,
    // and htmx sets location *after* that response — networkidle can therefore resolve while the
    // URL is still /admin/content/new. Wait for the edit URL instead of racing it.
    await page.waitForURL(/\/admin\/content\/[^/]+\/edit/, { timeout: 15000 })
    await page.waitForLoadState('networkidle', { timeout: 15000 })

    const firstSaveEditUrl = await getEditUrlFromPage(page)
    if (firstSaveEditUrl) {
      const idMatch = firstSaveEditUrl.match(/\/admin\/content\/([^/]+)\/edit/)
      createdContentId = idMatch?.[1] || null
      await page.goto(firstSaveEditUrl)
      await page.waitForLoadState('networkidle', { timeout: 15000 })
    } else {
      await gotoWithRetry(page, '/admin/content?collection=' + encodeURIComponent(collectionKey))
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      const contentLink = page.locator(`a:has-text("${title}")`).first()
      await expect(contentLink).toBeVisible({ timeout: 10000 })
      const href = await contentLink.getAttribute('href')
      const idMatch = href?.match(/\/admin\/content\/([^/]+)\/edit/)
      createdContentId = idMatch?.[1] || null
      if (href) {
        await page.goto(href)
        await page.waitForLoadState('networkidle', { timeout: 15000 })
      }
    }
    await expect(page.locator('form#content-form')).toBeVisible({ timeout: 10000 })

    const reopenedTeamGroup = page.locator('[data-structured-object][data-field-name="team"]').first()
    const reopenedTeamContent = reopenedTeamGroup.locator(':scope > .field-group-content')
    if ((await reopenedTeamContent.getAttribute('class'))?.includes('hidden')) {
      await reopenedTeamGroup.locator(':scope > .field-group-header').click()
      await expect(reopenedTeamContent).not.toHaveClass(/hidden/)
    }

    const editMembersField = page.locator('[data-structured-array][data-field-name="team__members"]').first()
    const editTopLevelMembers = editMembersField.locator(':scope > [data-structured-array-list] > .structured-array-item')
    await expect(editMembersField).toBeVisible()
    await addRootMemberAndWaitForCount(editMembersField, editTopLevelMembers, 2)
    await expect(editTopLevelMembers).toHaveCount(2)

    const newMember = editTopLevelMembers.nth(1)
    const newMemberFields = newMember.locator('[data-array-item-fields]').first()
    if ((await newMemberFields.getAttribute('class'))?.includes('hidden')) {
      await newMember.locator('[data-action="toggle-item"]').first().click()
      await expect(newMemberFields).not.toHaveClass(/hidden/)
    }
    await newMember.locator('input[name$="__name"]').first().fill('Added After Return')
    await expect
      .poll(async () =>
        newMember.locator('[data-structured-array][data-field-name$="__children"]').count(),
      )
      .toBeGreaterThan(0)
    const newMemberChildrenField = newMember
      .locator('[data-structured-array][data-field-name$="__children"]')
      .first()
    await expect(newMemberChildrenField).toBeVisible()
    await newMemberChildrenField.locator(':scope > .flex.items-center.justify-between.gap-3 > [data-action="add-item"]').click()

    const newMemberFirstChild = newMemberChildrenField.locator(':scope > [data-structured-array-list] > .structured-array-item').first()
    await expect(newMemberFirstChild).toBeVisible()
    const newMemberFirstChildFields = newMemberFirstChild.locator('[data-array-item-fields]').first()
    if ((await newMemberFirstChildFields.getAttribute('class'))?.includes('hidden')) {
      await newMemberFirstChild.locator('[data-action="toggle-item"]').first().click()
      await expect(newMemberFirstChildFields).not.toHaveClass(/hidden/)
    }
    await newMemberFirstChild.locator('input[name$="__name"]').first().fill('Child After Return')

    // Unlike the first save this one updates an existing document, so there is no HX-Redirect and
    // no URL change to wait on — and `networkidle` can resolve before the write has even been
    // issued. Reloading at that point re-reads the pre-save document and `team.members` comes
    // back with just the one item from the first save. Wait for the write to be acknowledged.
    //
    // The method matters: the form is `hx-post="/admin/content"` only while creating. Once the
    // document exists it switches to `hx-put="/admin/content/<id>"`, so matching POST alone never
    // fires here and the wait just burns its timeout.
    const [saveResponse] = await Promise.all([
      page.waitForResponse(
        (r) =>
          ['POST', 'PUT'].includes(r.request().method()) &&
          /^\/admin\/content(\/|$)/.test(new URL(r.url()).pathname),
        { timeout: 30000 }
      ),
      page.click('button[name="action"][value="save"]'),
    ])
    expect(saveResponse.ok(), `save returned ${saveResponse.status()}`).toBeTruthy()
    await page.waitForLoadState('networkidle', { timeout: 15000 })

    const secondSaveEditUrl = await getEditUrlFromPage(page)
    if (secondSaveEditUrl) {
      await gotoWithRetry(page, secondSaveEditUrl)
      await page.waitForLoadState('networkidle', { timeout: 15000 })
    } else if (createdContentId) {
      await gotoWithRetry(page, `/admin/content/${createdContentId}/edit`)
      await page.waitForLoadState('networkidle', { timeout: 15000 })
    } else {
      await gotoWithRetry(page, '/admin/content?collection=' + encodeURIComponent(collectionKey))
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      const contentLink = page.locator(`a:has-text("${title}")`).first()
      await expect(contentLink).toBeVisible({ timeout: 10000 })
      const href = await contentLink.getAttribute('href')
      if (href) {
        await page.goto(href)
        await page.waitForLoadState('networkidle', { timeout: 15000 })
      }
    }
    await expect(page.locator('form#content-form')).toBeVisible({ timeout: 10000 })

    const teamRaw = await page.locator('input[name="team"]').inputValue()
    const team = JSON.parse(teamRaw)
    expect(Array.isArray(team.members)).toBe(true)
    expect(team.members).toHaveLength(2)
    expect(team.members[1]?.name).toBe('Added After Return')
    expect(Array.isArray(team.members[1]?.children)).toBe(true)
    expect(team.members[1].children).toHaveLength(1)
    expect(team.members[1].children[0]?.name).toBe('Child After Return')

    if (createdContentId) {
      const deleteResponse = await page.request.delete(`/admin/content/${createdContentId}`)
      expect(deleteResponse.ok()).toBeTruthy()
    }
  })
})
