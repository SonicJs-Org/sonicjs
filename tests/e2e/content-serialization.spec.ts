import { test } from "./fixtures"
import { expect } from "./fixtures"
import type { Locator } from "./fixtures"
import type { Page } from "./fixtures"
import { ensureAdminUserExists } from "./utils/test-helpers"
import { loginAsAdmin } from "./utils/test-helpers"
import type { APIRequestContext } from "./fixtures"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 57-nested-array-serialization-scope.spec.ts", () => {
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
    // One click, one close. The confirm button routes through closeConfirmDialog(), which
    // guards against el-dialog v1 dropping a close that reverses its in-flight enter
    // transition. Re-clicking here would hide that regression and replay the deletion.
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 58-nested-object-serialization.spec.ts", () => {
  async function resolvePageBlocksCollectionKey(page: import('@playwright/test').Page): Promise<string | null> {
    await page.goto('/admin/content/new')
    await page.waitForLoadState('networkidle', { timeout: 15000 })

    const e2eTestLink = page
      .locator('a[href^="/admin/content/new?collection="]')
      .filter({ hasText: 'E2E Test' })
      .first()

    if (!(await e2eTestLink.isVisible({ timeout: 5000 }).catch(() => false))) {
      return null
    }

    const href = await e2eTestLink.getAttribute('href')
    const match = href?.match(/[?&]collection=([^&]+)/)
    return match?.[1] || null
  }

  test.describe('Nested Object Serialization @content', () => {
    test('should persist sibling flat child objects inside a nested parent object', async ({ page }) => {
      await loginAsAdmin(page)

      const collectionKey = await resolvePageBlocksCollectionKey(page)
      test.skip(!collectionKey, 'E2E Test collection not available')

      await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey!))
      await page.waitForLoadState('networkidle')
      await expect(page.locator('form#content-form')).toBeVisible()

      // Slugs are unique per collection, so a fixed one fails on the second local run.
      await page.fill('input[name="title"]', 'Opening Hours Serialization Test')
      await page.fill('input[name="slug"]', `opening-hours-serialization-test-${Date.now()}`)

      const openingHoursGroup = page
        .locator('[data-structured-object][data-field-name="openingHoursWeek"]')
        .first()
      await expect(openingHoursGroup).toBeVisible()

      const openingHoursContent = openingHoursGroup.locator(':scope > .field-group-content')
      if ((await openingHoursContent.getAttribute('class'))?.includes('hidden')) {
        await openingHoursGroup.locator(':scope > .field-group-header').click()
        await expect(openingHoursContent).not.toHaveClass(/hidden/)
      }

      await page.fill('input[name="openingHoursWeek__monday__opens"]', '09:00')
      await page.fill('input[name="openingHoursWeek__monday__closes"]', '17:00')
      await page.fill('input[name="openingHoursWeek__tuesday__opens"]', '10:00')
      await page.fill('input[name="openingHoursWeek__tuesday__closes"]', '18:00')
      await page.fill('input[name="openingHoursWeek__wednesday__opens"]', '11:00')
      await page.fill('input[name="openingHoursWeek__wednesday__closes"]', '19:00')

      const beforeSaveOpeningHours = JSON.parse(
        await page.locator('input[name="openingHoursWeek"]').inputValue(),
      )
      expect(beforeSaveOpeningHours.monday).toEqual({ closed: false, opens: '09:00', closes: '17:00' })
      expect(beforeSaveOpeningHours.tuesday).toEqual({ closed: false, opens: '10:00', closes: '18:00' })
      expect(beforeSaveOpeningHours.wednesday).toEqual({ closed: false, opens: '11:00', closes: '19:00' })

      await page.click('button[name="action"][value="save"]')
      // A new-document save answers the HTMX request with `HX-Redirect: /admin/content/<id>/edit`,
      // and htmx sets location *after* that response — networkidle can therefore resolve while the
      // URL is still /admin/content/new. Wait for the edit URL instead of racing it.
      await page.waitForURL(/\/admin\/content\/[^/]+\/edit/, { timeout: 15000 })
      await page.waitForLoadState('networkidle', { timeout: 15000 })

      const editUrl = page.url().includes('/edit')
        ? page.url()
        : await page
            .locator('a[href*="/admin/content/"][href*="/edit"]')
            .first()
            .getAttribute('href')

      if (!editUrl) {
        throw new Error('Could not resolve edit URL after saving content')
      }

      const contentIdMatch = editUrl.match(/\/admin\/content\/([^/]+)\/edit/)
      if (!contentIdMatch) {
        throw new Error(`Could not extract content ID from edit URL: ${editUrl}`)
      }
      const contentId = contentIdMatch[1]

      const apiResponse = await page.request.get(`/api/content/${contentId}`)
      expect(apiResponse.ok()).toBe(true)
      const apiContent = await apiResponse.json()
      expect(apiContent.data?.data?.openingHoursWeek?.monday).toEqual({
        closed: false,
        opens: '09:00',
        closes: '17:00',
      })
      expect(apiContent.data?.data?.openingHoursWeek?.tuesday).toEqual({
        closed: false,
        opens: '10:00',
        closes: '18:00',
      })
      expect(apiContent.data?.data?.openingHoursWeek?.wednesday).toEqual({
        closed: false,
        opens: '11:00',
        closes: '19:00',
      })

      await page.goto(editUrl)
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      await expect(page.locator('form#content-form')).toBeVisible()

      await expect(page.locator('input[name="openingHoursWeek__monday__opens"]')).toHaveValue('09:00')
      await expect(page.locator('input[name="openingHoursWeek__tuesday__opens"]')).toHaveValue('10:00')
      await expect(page.locator('input[name="openingHoursWeek__wednesday__opens"]')).toHaveValue('11:00')

      const serializedOpeningHours = JSON.parse(
        await page.locator('input[name="openingHoursWeek"]').inputValue(),
      )
      expect(serializedOpeningHours.monday).toEqual({ closed: false, opens: '09:00', closes: '17:00' })
      expect(serializedOpeningHours.tuesday).toEqual({ closed: false, opens: '10:00', closes: '18:00' })
      expect(serializedOpeningHours.wednesday).toEqual({ closed: false, opens: '11:00', closes: '19:00' })

      await page.fill('input[name="title"]', 'Opening Hours Serialization Test Updated')
      await page.click('button[name="action"][value="save"]')
      await page.waitForLoadState('networkidle', { timeout: 15000 })

      const secondEditUrl = page.url().includes('/edit')
        ? page.url()
        : await page
            .locator('a[href*="/admin/content/"][href*="/edit"]')
            .first()
            .getAttribute('href')

      if (!secondEditUrl) {
        throw new Error('Could not resolve edit URL after second save')
      }

      await page.goto(secondEditUrl)
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      await expect(page.locator('form#content-form')).toBeVisible()

      const secondSerializedOpeningHours = JSON.parse(
        await page.locator('input[name="openingHoursWeek"]').inputValue(),
      )
      expect(secondSerializedOpeningHours.monday).toEqual({ closed: false, opens: '09:00', closes: '17:00' })
      expect(secondSerializedOpeningHours.tuesday).toEqual({ closed: false, opens: '10:00', closes: '18:00' })
      expect(secondSerializedOpeningHours.wednesday).toEqual({ closed: false, opens: '11:00', closes: '19:00' })

      await expect(page.locator('input[name="openingHoursWeek__monday__opens"]')).toHaveValue('09:00')
      await expect(page.locator('input[name="openingHoursWeek__tuesday__opens"]')).toHaveValue('10:00')
      await expect(page.locator('input[name="openingHoursWeek__wednesday__opens"]')).toHaveValue('11:00')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 59-array-media-picker-targeting.spec.ts", () => {
  type UploadedMedia = {
    id: string
    filename: string
  }

  async function uploadTestImage(
    request: APIRequestContext,
    filenamePrefix: string,
  ): Promise<UploadedMedia> {
    const testImageBuffer = Buffer.from([
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
      0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43,
      0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
      0x09, 0x08, 0x0a, 0x0c, 0x14, 0x0d, 0x0c, 0x0b, 0x0b, 0x0c, 0x19, 0x12,
      0x13, 0x0f, 0x14, 0x1d, 0x1a, 0x1f, 0x1e, 0x1d, 0x1a, 0x1c, 0x1c, 0x20,
      0x24, 0x2e, 0x27, 0x20, 0x22, 0x2c, 0x23, 0x1c, 0x1c, 0x28, 0x37, 0x29,
      0x2c, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1f, 0x27, 0x39, 0x3d, 0x38, 0x32,
      0x3c, 0x2e, 0x33, 0x34, 0x32, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x01,
      0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
      0xff, 0xc4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xff, 0xc4,
      0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xda, 0x00, 0x0c,
      0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3f, 0x00, 0x80, 0xff, 0xd9,
    ])

    const formData = new FormData()
    const blob = new Blob([testImageBuffer], { type: 'image/jpeg' })
    const timestamp = Date.now()
    const uploadedFileName = `${filenamePrefix}-${timestamp}.jpg`
    formData.append('files', blob, uploadedFileName)
    formData.append('folder', 'uploads')

    const uploadResponse = await request.post('/api/media/upload-multiple', {
      multipart: formData,
    })

    expect(uploadResponse.ok()).toBeTruthy()
    const uploadResult = await uploadResponse.json()
    expect(uploadResult.uploaded).toBeDefined()
    expect(uploadResult.uploaded.length).toBe(1)

    return uploadResult.uploaded[0] as UploadedMedia
  }

  async function resolvePageBlocksCollectionKey(page: Page): Promise<string | null> {
    await page.goto('/admin/content/new')
    await page.waitForLoadState('networkidle', { timeout: 15000 })

    const e2eTestLink = page
      .locator('a[href^="/admin/content/new?collection="]')
      .filter({ hasText: 'E2E Test' })
      .first()

    if (!(await e2eTestLink.isVisible({ timeout: 5000 }).catch(() => false))) {
      return null
    }

    const href = await e2eTestLink.getAttribute('href')
    const match = href?.match(/[?&]collection=([^&]+)/)
    return match?.[1] || null
  }

  async function ensureExpandedArrayItem(item: ReturnType<Page['locator']>) {
    const itemFields = item.locator('[data-array-item-fields]').first()
    const itemClasses = (await itemFields.getAttribute('class')) || ''
    if (itemClasses.includes('hidden')) {
      await item.locator('[data-action="toggle-item"]').first().click()
      await expect(itemFields).not.toHaveClass(/hidden/)
    }
  }

  async function selectMediaForField(
    page: Page,
    field: ReturnType<Page['locator']>,
    uploadedMediaId: string,
  ) {
    const selectMediaButton = field.locator('button:has-text("Select Media")').first()
    await expect(selectMediaButton).toBeVisible()
    await selectMediaButton.click()

    const modal = page.locator('#media-selector-modal')
    await expect(modal).toBeVisible({ timeout: 10000 })

    const selectButton = page
      .locator(`[data-media-id="${uploadedMediaId}"] button:has-text("Select")`)
      .first()
    await expect(selectButton).toBeVisible({ timeout: 10000 })
    await selectButton.click()

    await modal.locator('button:has-text("OK")').click()
    await expect(modal).toBeHidden({ timeout: 5000 })
  }

  test.describe('Array Media Picker Targeting @content @media', () => {
    let uploadedMediaA: UploadedMedia | null = null
    let uploadedMediaB: UploadedMedia | null = null

    test.beforeEach(async ({ page, context }) => {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)

      uploadedMediaA = await uploadTestImage(context.request, 'array-media-a')
      uploadedMediaB = await uploadTestImage(context.request, 'array-media-b')
    })

    test.afterEach(async ({ context }) => {
      const fileIds = [uploadedMediaA?.id, uploadedMediaB?.id].filter(Boolean)
      if (fileIds.length > 0) {
        await context.request.post('/api/media/bulk-delete', {
          data: { fileIds },
        }).catch(() => {})
      }
    })

    test('should target the correct structured-array row when selecting media', async ({ page }) => {
      let createdContentId: string | null = null
      const title = `Gallery Media Targeting ${Date.now()}`
      const slug = `gallery-media-targeting-${Date.now()}`

      const collectionKey = await resolvePageBlocksCollectionKey(page)
      test.skip(!collectionKey, 'E2E Test collection not available')

      await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey!))
      await page.waitForLoadState('networkidle', { timeout: 15000 })
      await expect(page.locator('form#content-form')).toBeVisible()

      await page.fill('input[name="title"]', title)
      await page.fill('input[name="slug"]', slug)

      const blocksField = page.locator('[data-field-name="body"]').first()
      await expect(blocksField).toBeVisible()

      await blocksField.locator('[data-role="block-type-select"]').selectOption('gallery')
      await blocksField.locator('[data-action="add-block"]').click()

      const galleryBlock = blocksField.locator('.blocks-item').first()
      await expect(galleryBlock).toBeVisible()
      const galleryBlockContent = galleryBlock.locator('[data-block-content]')
      const galleryBlockContentClasses = (await galleryBlockContent.getAttribute('class')) || ''
      if (galleryBlockContentClasses.includes('hidden')) {
        await galleryBlock.locator('[data-action="toggle-block"]').first().click()
        await expect(galleryBlockContent).not.toHaveClass(/hidden/)
      }

      await galleryBlock.locator('[data-block-field="heading"] input').fill('Targeted gallery')

      const imagesField = galleryBlock.locator('[data-block-field="images"] [data-structured-array]').first()
      const topLevelRows = imagesField.locator(':scope > [data-structured-array-list] > .structured-array-item')

      await imagesField.locator(':scope > .flex.items-center.justify-between.gap-3 [data-action="add-item"]').click()
      await expect(topLevelRows).toHaveCount(1)

      const firstRow = topLevelRows.first()
      await ensureExpandedArrayItem(firstRow)
      const firstImageField = firstRow.locator('[data-structured-field="image"]').first()
      await selectMediaForField(page, firstImageField, uploadedMediaA!.id)

      const firstHiddenInput = firstImageField.locator('input[type="hidden"]').first()
      await expect(firstHiddenInput).not.toHaveValue('')
      const firstSelectedValue = await firstHiddenInput.inputValue()

      await imagesField.locator(':scope > .flex.items-center.justify-between.gap-3 [data-action="add-item"]').click()
      await expect(topLevelRows).toHaveCount(2)

      const secondRow = topLevelRows.nth(1)
      await ensureExpandedArrayItem(secondRow)
      const secondImageField = secondRow.locator('[data-structured-field="image"]').first()
      await selectMediaForField(page, secondImageField, uploadedMediaB!.id)

      const secondHiddenInput = secondImageField.locator('input[type="hidden"]').first()
      await expect(secondHiddenInput).not.toHaveValue('')
      const secondSelectedValue = await secondHiddenInput.inputValue()
      expect(secondSelectedValue).not.toBe(firstSelectedValue)
      await expect(firstHiddenInput).toHaveValue(firstSelectedValue)

      await page.click('button[name="action"][value="save"]')
      await page.waitForURL(/\/admin\/content\/[^/]+\/edit|\/admin\/content\?/, { timeout: 15000 })

      try {
        const editUrlMatch = page.url().match(/\/admin\/content\/([^/]+)\/edit/)
        if (editUrlMatch?.[1]) {
          createdContentId = editUrlMatch[1]
        } else {
          await page.goto('/admin/content?collection=' + encodeURIComponent(collectionKey!))
          await page.waitForLoadState('networkidle', { timeout: 15000 })
          const contentLink = page.locator(`a:has-text("${title}")`).first()
          await expect(contentLink).toBeVisible({ timeout: 10000 })
          const href = await contentLink.getAttribute('href')
          const match = href?.match(/\/admin\/content\/([^/]+)\/edit/)
          createdContentId = match?.[1] || null
          await contentLink.click()
        }

        const reloadedGalleryBlock = page.locator('[data-field-name="body"] .blocks-item').first()
        const reloadedGalleryContent = reloadedGalleryBlock.locator('[data-block-content]')
        if (((await reloadedGalleryContent.getAttribute('class')) || '').includes('hidden')) {
          await reloadedGalleryBlock.locator('button[data-action="toggle-block"]').first().click()
          await expect(reloadedGalleryContent).not.toHaveClass(/hidden/)
        }

        const reloadedImagesField = reloadedGalleryBlock
          .locator('[data-block-field="images"] [data-structured-array]')
          .first()
        const reloadedRows = reloadedImagesField.locator(
          ':scope > [data-structured-array-list] > .structured-array-item',
        )
        await expect(reloadedRows).toHaveCount(2)

        const reloadedFirstRow = reloadedRows.first()
        const reloadedSecondRow = reloadedRows.nth(1)
        await ensureExpandedArrayItem(reloadedFirstRow)
        await ensureExpandedArrayItem(reloadedSecondRow)

        const reloadedFirstHiddenInput = reloadedFirstRow
          .locator('[data-structured-field="image"] input[type="hidden"]')
          .first()
        const reloadedSecondHiddenInput = reloadedSecondRow
          .locator('[data-structured-field="image"] input[type="hidden"]')
          .first()

        await expect(reloadedFirstHiddenInput).toHaveValue(firstSelectedValue)
        await expect(reloadedSecondHiddenInput).toHaveValue(secondSelectedValue)
      } finally {
        if (createdContentId) {
          const deleteResponse = await page.request.delete(`/admin/content/${createdContentId}`)
          expect(deleteResponse.ok()).toBeTruthy()
        }
      }
    })
  })
})
