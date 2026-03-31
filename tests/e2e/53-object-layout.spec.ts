import { expect, test } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Object Layout', () => {
  test('should render flat objects expanded and nested objects collapsed by default', async ({ page }) => {
    await loginAsAdmin(page)

    await page.goto('/admin/content/new')
    const pageBlocksLink = page
      .locator('a[href^="/admin/content/new?collection="]')
      .filter({ hasText: 'Page Blocks' })
    await expect(pageBlocksLink).toBeVisible()
    await pageBlocksLink.click()
    await page.waitForLoadState('networkidle')
    await expect(page.locator('form#content-form')).toBeVisible()

    // Top-level flat object should render without collapsible header and stay visible.
    const flatSeoObject = page.locator('[data-structured-object][data-field-name="seo"]')
    await expect(flatSeoObject).toBeVisible()
    await expect(flatSeoObject.locator('.field-group-header')).toHaveCount(0)
    await expect(flatSeoObject.locator('input[name="seo__title"]')).toBeVisible()

    const blocksField = page.locator('[data-field-name="body"]')
    await expect(blocksField).toBeVisible()
    await blocksField.locator('[data-role="block-type-select"]').selectOption('hero')
    await blocksField.locator('[data-action="add-block"]').click()

    const heroBlock = blocksField.locator('.blocks-item').first()
    await expect(heroBlock).toBeVisible()

    const blockContent = heroBlock.locator('[data-block-content]')
    if (await blockContent.isHidden()) {
      await heroBlock.locator('[data-action="toggle-block"]').first().click()
      await expect(blockContent).toBeVisible()
    }

    // Nested object inside block should render as collapsible and start collapsed.
    const nestedCtaObject = heroBlock
      .locator('[data-block-field="ctaPrimary"] .field-group')
      .filter({ has: page.getByRole('heading', { name: 'Primary CTA' }) })
      .first()
    await expect(nestedCtaObject).toBeVisible()

    const nestedHeader = nestedCtaObject.locator(':scope > .field-group-header')
    const nestedContent = nestedCtaObject.locator(':scope > .field-group-content')
    const nestedIcon = nestedCtaObject.locator(':scope > .field-group-header svg[id$="-icon"]')

    await expect(nestedHeader).toHaveCount(1)
    await expect(nestedContent).toHaveClass(/hidden/)
    await expect(nestedIcon).toHaveClass(/-rotate-90/)

    await nestedHeader.click()
    await expect(nestedContent).not.toHaveClass(/hidden/)
    await expect(nestedIcon).not.toHaveClass(/-rotate-90/)
  })
})
