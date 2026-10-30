import { test, expect } from './fixtures'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

test.describe('Hero CTA Style Persistence @content', () => {
  test('should keep CTA styles after unrelated second save', async ({ page }) => {
    // Seven full page loads (login, /admin/content/new, the collection pick, two saves and
    // their redirects, the final reload) plus the cleanup round trip. The 60s this replaces was
    // *below* the suite default, so the test had opted itself out of the CI budget it needed:
    // against a cold preview one admin page load has been measured at ~10s p90.
    test.setTimeout(180000)
    let contentId: string | null = null
    const title = `Hero CTA Persist ${Date.now()}`
    const updatedTitle = `${title} updated`
    const tryExtractContentIdFromHref = (href: string | null) => {
      const match = href?.match(/\/admin\/content\/([^/]+)\/edit/)
      return match?.[1] || null
    }
    try {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)

      await page.goto('/admin/content/new')
      const e2eTestLink = page.locator('a[href^="/admin/content/new?collection="]').filter({ hasText: 'E2E Test' })
      await expect(e2eTestLink).toBeVisible()
      await e2eTestLink.click()

      await page.waitForLoadState('networkidle')
      await expect(page.locator('form#content-form')).toBeVisible()

      await page.fill('input[name="title"]', title)
      await page.fill('input[name="slug"]', `hero-cta-persist-${Date.now()}`)

      const blocksField = page.locator('[data-field-name="body"]')
      await blocksField.locator('[data-role="block-type-select"]').selectOption('hero')
      await blocksField.locator('[data-action="add-block"]').click()

      const firstBlock = blocksField.locator('.blocks-item').first()
      await firstBlock.locator('[data-block-field="heading"] input').fill('Hero heading')

      const ctaPrimary = firstBlock.locator('[data-block-field="ctaPrimary"]')
      const ctaPrimaryLabel = ctaPrimary.locator('input[name$="__label"]')
      if (!(await ctaPrimaryLabel.isVisible())) {
        await ctaPrimary.locator('.field-group-header').first().click()
        await expect(ctaPrimaryLabel).toBeVisible()
      }
      const ctaPrimaryMode = ctaPrimary.locator('select[name$="__mode"]')
      if (!(await ctaPrimaryMode.isVisible())) {
        const ctaPrimaryLinkHeader = ctaPrimary.locator('[data-field-name$="__link"] .field-group-header').first()
        if (await ctaPrimaryLinkHeader.count()) {
          await ctaPrimaryLinkHeader.click()
        }
        await expect(ctaPrimaryMode).toBeVisible()
      }
      await ctaPrimary.locator('input[name$="__label"]').fill('Primary CTA')
      await ctaPrimaryMode.selectOption('external')
      await ctaPrimary.locator('input[name$="__url"]').fill('https://example.com/primary')
      await ctaPrimary.locator('select[name$="__style"]').selectOption('secondary')

      const ctaSecondary = firstBlock.locator('[data-block-field="ctaSecondary"]')
      const ctaSecondaryLabel = ctaSecondary.locator('input[name$="__label"]')
      if (!(await ctaSecondaryLabel.isVisible())) {
        await ctaSecondary.locator('.field-group-header').first().click()
        await expect(ctaSecondaryLabel).toBeVisible()
      }
      await ctaSecondary.locator('input[name$="__label"]').fill('Secondary CTA')
      await ctaSecondary.locator('select[name$="__style"]').selectOption('secondary')

      // A new-document save answers the HTMX request with `HX-Redirect:
      // /admin/content/<id>/edit`, and htmx only sets location once that response lands. The
      // fixed 2s raced it: on a cold preview the POST had not returned, so the `goto` below
      // cancelled the save in flight. Waiting for the redirect also hands us the id and a fresh
      // server render of the edit page — which is all the trip through the content list was
      // for — and drops a title match that leftover rows from earlier runs could satisfy.
      await page.click('button[name="action"][value="save"]')
      await page.waitForURL(/\/admin\/content\/[^/]+\/edit/, { timeout: 30000 })
      contentId = page.url().match(/\/admin\/content\/([^/]+)\/edit/)?.[1] || null
      await expect(page.locator('form#content-form')).toBeVisible()

      const reloadedBlocksField = page.locator('[data-field-name="body"]')
      const reloadedFirstBlock = reloadedBlocksField.locator('.blocks-item').first()
      const reloadedBlockContent = reloadedFirstBlock.locator('[data-block-content]')
      const reloadedBlockClass = (await reloadedBlockContent.getAttribute('class')) || ''
      if (reloadedBlockClass.includes('hidden')) {
        await reloadedFirstBlock.locator('button[data-action="toggle-block"]').first().click()
        await expect(reloadedBlockContent).not.toHaveClass(/hidden/)
      }

      const reloadedCtaPrimary = reloadedFirstBlock.locator('[data-block-field="ctaPrimary"]')
      const reloadedPrimaryStyle = reloadedCtaPrimary.locator('select[name$="__style"]')
      if (!(await reloadedPrimaryStyle.isVisible())) {
        await reloadedCtaPrimary.locator('.field-group-header').first().click()
        await expect(reloadedPrimaryStyle).toBeVisible()
      }

      const reloadedCtaSecondary = reloadedFirstBlock.locator('[data-block-field="ctaSecondary"]')
      const reloadedSecondaryStyle = reloadedCtaSecondary.locator('select[name$="__style"]')
      if (!(await reloadedSecondaryStyle.isVisible())) {
        await reloadedCtaSecondary.locator('.field-group-header').first().click()
        await expect(reloadedSecondaryStyle).toBeVisible()
      }

      await expect(reloadedPrimaryStyle).toHaveValue('secondary')
      await expect(reloadedSecondaryStyle).toHaveValue('secondary')

      // Unlike the create above, an edit-page `save` does not navigate: the document-model
      // update path answers the PUT with an inline `#form-messages` banner and stays put
      // (admin-content.ts, "save / save_and_publish: stay on page"). So wait on the PUT itself.
      // That is what the fixed 2s stood in for, and it is the thing that matters here — once the
      // response is in, the write is committed and the reload below cannot cancel it. Keying on
      // banner text instead would be fragile in a different way: the create redirect already put
      // a success message on this page.
      await page.fill('input[name="title"]', updatedTitle)
      const secondSaveResponse = page.waitForResponse(
        (response) =>
          response.request().method() === 'PUT' &&
          /^\/admin\/content\/[^/]+$/.test(new URL(response.url()).pathname),
        { timeout: 30000 }
      )
      await page.click('button[name="action"][value="save"]')
      expect((await secondSaveResponse).ok()).toBeTruthy()

      if (contentId) {
        await page.goto(`/admin/content/${contentId}/edit`)
      } else {
        await page.reload()
      }

      const secondBlocksField = page.locator('[data-field-name="body"]')
      const secondFirstBlock = secondBlocksField.locator('.blocks-item').first()
      const secondBlockContent = secondFirstBlock.locator('[data-block-content]')
      const secondBlockClass = (await secondBlockContent.getAttribute('class')) || ''
      if (secondBlockClass.includes('hidden')) {
        await secondFirstBlock.locator('button[data-action="toggle-block"]').first().click()
        await expect(secondBlockContent).not.toHaveClass(/hidden/)
      }

      const secondCtaPrimary = secondFirstBlock.locator('[data-block-field="ctaPrimary"]')
      const secondPrimaryStyle = secondCtaPrimary.locator('select[name$="__style"]')
      if (!(await secondPrimaryStyle.isVisible())) {
        await secondCtaPrimary.locator('.field-group-header').first().click()
        await expect(secondPrimaryStyle).toBeVisible()
      }

      const secondCtaSecondary = secondFirstBlock.locator('[data-block-field="ctaSecondary"]')
      const secondSecondaryStyle = secondCtaSecondary.locator('select[name$="__style"]')
      if (!(await secondSecondaryStyle.isVisible())) {
        await secondCtaSecondary.locator('.field-group-header').first().click()
        await expect(secondSecondaryStyle).toBeVisible()
      }

      await expect(secondPrimaryStyle).toHaveValue('secondary')
      await expect(secondSecondaryStyle).toHaveValue('secondary')
    } finally {
      try {
        if (page.isClosed()) {
          return
        }

        if (!contentId) {
          await page.goto('/admin/content?collection=e2e_test')
          const updatedLink = page.locator(`a:has-text("${updatedTitle}")`).first()
          if (await updatedLink.count()) {
            contentId = tryExtractContentIdFromHref(await updatedLink.getAttribute('href'))
          }
          if (!contentId) {
            const originalLink = page.locator(`a:has-text("${title}")`).first()
            if (await originalLink.count()) {
              contentId = tryExtractContentIdFromHref(await originalLink.getAttribute('href'))
            }
          }
        }

        if (contentId) {
          const apiDelete = await page.request.delete(`/api/content/${contentId}`)
          if (!apiDelete.ok()) {
            await page.request.delete(`/admin/content/${contentId}`)
          }
        }
      } catch {
        // Best-effort cleanup; don't mask the actual test failure.
      }
    }
  })
})
