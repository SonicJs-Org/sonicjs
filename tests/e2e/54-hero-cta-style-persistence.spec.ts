import { test, expect } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

test.describe('Hero CTA Style Persistence', () => {
  test('should keep CTA styles after unrelated second save', async ({ page }) => {
    test.setTimeout(60000)
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
      const pageBlocksLink = page.locator('a[href^="/admin/content/new?collection="]').filter({ hasText: 'Page Blocks' })
      await expect(pageBlocksLink).toBeVisible()
      await pageBlocksLink.click()

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

      await page.click('button[name="action"][value="save_and_publish"]')
      await page.waitForTimeout(2000)

      await page.goto('/admin/content?collection=page_blocks')
      const contentLink = page.locator(`a:has-text("${title}")`).first()
      await expect(contentLink).toBeVisible()
      const href = await contentLink.getAttribute('href')
      const match = href?.match(/\/admin\/content\/([^/]+)\/edit/)
      contentId = match?.[1] || null
      await contentLink.click()

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

      await page.fill('input[name="title"]', updatedTitle)
      await page.click('button[name="action"][value="save_and_publish"]')
      await page.waitForTimeout(2000)

      if (contentId) {
        await page.goto(`/admin/content/${contentId}/edit`)
      } else {
        await page.goto('/admin/content?collection=page_blocks')
        await page.locator(`a:has-text("${updatedTitle}")`).first().click()
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
          await page.goto('/admin/content?collection=page_blocks')
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
