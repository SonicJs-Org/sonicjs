import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

// Skip in CI - depends on E2E Test collection which may not be configured in CI environment
test.describe.skip('Content Blocks (Code-Based Collections) @content', () => {
  test('should allow adding block content in code-based collections', async ({ page }) => {
    await loginAsAdmin(page)

    await page.goto('/admin/content/new')

    const e2eTestLink = page.locator('a[href^="/admin/content/new?collection="]').filter({ hasText: 'E2E Test' })
    await expect(e2eTestLink).toBeVisible()
    await e2eTestLink.click()

    await page.waitForLoadState('networkidle')
    await expect(page.locator('form#content-form')).toBeVisible()

    await page.fill('input[name="title"]', 'Blocks Page')
    await page.fill('input[name="slug"]', 'blocks-page')

    const seoField = page.locator('[data-field-name="seo"]')
    await expect(seoField).toBeVisible()
    await seoField.locator('input[name="seo__title"]').fill('SEO Title')
    await seoField.locator('textarea[name="seo__description"]').fill('SEO description text')

    const blocksField = page.locator('[data-field-name="body"]')
    await expect(blocksField).toBeVisible()

    await blocksField.locator('[data-role="block-type-select"]').selectOption('text')
    await blocksField.locator('[data-action="add-block"]').click()

    const firstBlock = blocksField.locator('.blocks-item').first()
    await firstBlock.locator('[data-block-field="heading"] input').fill('Hello')
    await firstBlock.locator('[data-block-field="body"] textarea').fill('First block body')

    await blocksField.locator('[data-role="block-type-select"]').selectOption('callToAction')
    await blocksField.locator('[data-action="add-block"]').click()

    const secondBlock = blocksField.locator('.blocks-item').nth(1)
    await secondBlock.locator('[data-block-field="title"] input').fill('Get started')
    await secondBlock.locator('[data-block-field="body"] textarea').fill('CTA copy')
    await secondBlock.locator('[data-block-field="buttonLabel"] input').fill('Sign up')
    await secondBlock.locator('[data-block-field="buttonUrl"] input').fill('https://example.com')

    const dragHandle = secondBlock.locator('[data-action="drag-handle"]')
    await dragHandle.dispatchEvent('pointerdown')
    await secondBlock.dragTo(firstBlock)

    let hiddenValue = await blocksField.locator('input[type="hidden"][name="body"]').inputValue()
    let parsed = JSON.parse(hiddenValue)

    if (parsed[0]?.blockType !== 'callToAction') {
      await secondBlock.locator('[data-action="move-up"]').click()
      hiddenValue = await blocksField.locator('input[type="hidden"][name="body"]').inputValue()
      parsed = JSON.parse(hiddenValue)
    }

    expect(parsed[0].blockType).toBe('callToAction')
    expect(parsed[1].blockType).toBe('text')

    const seoHiddenValue = await seoField.locator('input[type="hidden"][name="seo"]').inputValue()
    const seoParsed = JSON.parse(seoHiddenValue)
    expect(seoParsed.title).toBe('SEO Title')
    expect(seoParsed.description).toBe('SEO description text')

    await page.click('button[type="submit"][value="save"]')
    await page.waitForURL(/\/admin\/content\?collection=/)
    await expect(page.locator('table')).toContainText('Blocks Page')
    await expect(page.locator('table')).toContainText('blocks-page')
  })
})
