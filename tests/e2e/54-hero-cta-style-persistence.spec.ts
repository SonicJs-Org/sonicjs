import { test, expect } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

test.describe('Hero CTA Style Persistence', () => {
  test('should keep CTA styles after unrelated second save', async ({ page }) => {
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
      await ctaPrimary.locator('input[name$="__label"]').fill('Primary CTA')
      await ctaPrimary.locator('select[name$="__mode"]').selectOption('external')
      await ctaPrimary.locator('input[name$="__url"]').fill('https://example.com/primary')
      await ctaPrimary.locator('select[name$="__style"]').selectOption('secondary')

      const ctaSecondary = firstBlock.locator('[data-block-field="ctaSecondary"]')
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

      const bodyHiddenValueAfterFirstSave = await page.locator('input[name="body"]').inputValue()
      const parsedAfterFirstSave = JSON.parse(bodyHiddenValueAfterFirstSave)
      expect(parsedAfterFirstSave[0]?.ctaPrimary?.style).toBe('secondary')
      expect(parsedAfterFirstSave[0]?.ctaSecondary?.style).toBe('secondary')

      await page.fill('input[name="title"]', updatedTitle)
      await page.click('button[name="action"][value="save_and_publish"]')
      await page.waitForTimeout(2000)

      if (contentId) {
        await page.goto(`/admin/content/${contentId}/edit`)
      } else {
        await page.goto('/admin/content?collection=page_blocks')
        await page.locator(`a:has-text("${updatedTitle}")`).first().click()
      }

      const bodyHiddenValueAfterSecondSave = await page.locator('input[name="body"]').inputValue()
      const parsedAfterSecondSave = JSON.parse(bodyHiddenValueAfterSecondSave)
      expect(parsedAfterSecondSave[0]?.ctaPrimary?.style).toBe('secondary')
      expect(parsedAfterSecondSave[0]?.ctaSecondary?.style).toBe('secondary')
    } finally {
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
    }
  })
})
