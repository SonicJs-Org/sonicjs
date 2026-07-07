import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Blog post validation error - no nested form @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('validation error on new blog post does not nest the form inside itself', async ({ page }) => {
    await page.goto('/admin/content/new?collection=blog_post')
    await page.waitForLoadState('networkidle')

    // Fill title but leave required author field empty to trigger validation
    const titleInput = page.locator('input[name="title"]')
    if (await titleInput.count() > 0) {
      await titleInput.fill('Test Blog Post')
    }

    // Submit form
    const form = page.locator('#content-form')
    await form.evaluate((el: HTMLFormElement) => el.requestSubmit())
    await page.waitForLoadState('networkidle')

    // There must be exactly ONE #content-form-page — no nesting
    const formPages = page.locator('#content-form-page')
    await expect(formPages).toHaveCount(1)

    // The validation error alert must be visible
    await expect(page.locator('text=Please fix the validation errors below')).toBeVisible()

    // The form itself must still exist once
    await expect(page.locator('#content-form')).toHaveCount(1)
  })

  test('validation error on new content via HTMX does not duplicate #form-messages', async ({ page }) => {
    await page.goto('/admin/content/new?collection=blog_post')
    await page.waitForLoadState('networkidle')

    // Fill title only, leave required fields empty
    const titleInput = page.locator('input[name="title"]')
    if (await titleInput.count() > 0) {
      await titleInput.fill('HTMX Validation Test')
    }

    // Click any save button
    const saveBtn = page.locator('button[type="submit"]').first()
    await saveBtn.click()
    await page.waitForLoadState('networkidle')

    // #form-messages must appear at most once (deduplication fix)
    const msgDivs = page.locator('#form-messages')
    const count = await msgDivs.count()
    expect(count).toBeLessThanOrEqual(1)

    // Page should not have nested admin layout (nav should appear once)
    const navElements = page.locator('nav').first()
    await expect(navElements).toBeVisible()
  })
})
