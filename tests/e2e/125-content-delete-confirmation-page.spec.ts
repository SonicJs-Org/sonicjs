import { test, expect, Page } from '@playwright/test'
import { loginAsAdmin, saveNewContent } from './utils/test-helpers'

const NEW_RECORD_FORM = '/admin/content/new?collection=e2e_test'

type Record = { id: string; title: string; slug: string }

async function createRecord(page: Page, label = 'Delete test'): Promise<Record> {
  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const title = `${label} ${stamp}`
  const slug = `${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${stamp}`

  await page.goto(NEW_RECORD_FORM)
  await page.fill('input[name="title"]', title)
  await page.fill('input[name="slug"]', slug)
  await page.selectOption('select[name="status"]', 'draft')

  const editPath = await saveNewContent(page, () =>
    page.locator('button[type="submit"]').filter({ hasText: /Save|Create/ }).first().click()
  )
  return { id: editPath.split('/')[3], title, slug }
}

test.describe('Content Delete Confirmation Page @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('delete button navigates to confirmation page', async ({ page }) => {
    const record = await createRecord(page)

    // Should be on edit page after creation
    await expect(page).toHaveURL(new RegExp(`/admin/content/${record.id}/edit`))

    // Find delete link
    const deleteLink = page.locator('a:has-text("Delete Content")')
    await expect(deleteLink).toBeVisible()

    // Verify href points to delete confirmation
    const href = await deleteLink.getAttribute('href')
    expect(href).toContain(`/admin/content/${record.id}/delete`)

    // Navigate to confirmation page
    await deleteLink.click()
    await page.waitForURL(`**/admin/content/${record.id}/delete**`)

    // Verify confirmation page elements
    await expect(page.locator('h1:has-text("Delete Content")')).toBeVisible()
    await expect(page.locator('text=Review before permanently removing')).toBeVisible()
    await expect(page.locator('text=removed from the site and hidden from all lists')).toBeVisible()

    // Verify content title displayed
    await expect(page.locator(`text=${record.title}`)).toBeVisible()

    // Verify action buttons
    await expect(page.locator('a:has-text("Cancel")')).toBeVisible()
    await expect(page.locator('button:has-text("Delete Content")')).toBeVisible()
  })

  test('cancel button returns to edit page', async ({ page }) => {
    const record = await createRecord(page, 'Cancel test')

    await page.goto(`/admin/content/${record.id}/delete`)
    await expect(page.locator('h1:has-text("Delete Content")')).toBeVisible()

    // Click cancel
    await page.locator('a:has-text("Cancel")').click()
    await page.waitForURL(`**/admin/content/${record.id}/edit**`)

    // Should be back on edit page
    await expect(page.locator('h1:has-text("Edit")')).toBeVisible()
  })

  test('delete permanently removes content and redirects', async ({ page }) => {
    const record = await createRecord(page, 'Perm delete')

    await page.goto(`/admin/content/${record.id}/delete`)
    await expect(page.locator('h1:has-text("Delete Content")')).toBeVisible()

    // Confirm delete
    await page.locator('button:has-text("Delete Content")').click()

    // Should redirect to content list
    await page.waitForURL('**/admin/content**')
    expect(page.url()).not.toContain(record.id)

    // Verify content is gone - the edit page for a deleted record must not render the editor
    await page.goto(`/admin/content/${record.id}/edit`)
    const finalUrl = page.url()
    const stillOnEditPage = finalUrl.includes(`/admin/content/${record.id}/edit`)
    if (stillOnEditPage) {
      await expect(page.locator('text=Content not found')).toBeVisible()
    } else {
      expect(finalUrl).not.toContain(record.id)
    }
  })

  test('confirmation page shows content metadata', async ({ page }) => {
    const record = await createRecord(page, 'Metadata test')

    await page.goto(`/admin/content/${record.id}/delete`)

    // Check metadata labels
    await expect(page.locator('dt:has-text("Title")')).toBeVisible()
    await expect(page.locator('dt:has-text("Collection")')).toBeVisible()
    await expect(page.locator('dt:has-text("Slug")')).toBeVisible()
    await expect(page.locator('dt:has-text("Status")')).toBeVisible()
    await expect(page.locator('dt:has-text("Created")')).toBeVisible()
    await expect(page.locator('dt:has-text("Last Updated")')).toBeVisible()
    await expect(page.locator('dt:has-text("ID")')).toBeVisible()

    // Verify values
    await expect(page.locator(`dd:has-text("${record.title}")`)).toBeVisible()
    await expect(page.locator(`dd:has-text("${record.slug}")`)).toBeVisible()
  })

  test('nonexistent content redirects to list', async ({ page }) => {
    await page.goto('/admin/content/nonexistent-id-12345/delete')
    await page.waitForURL('**/admin/content**')
    expect(page.url()).not.toContain('nonexistent-id-12345')
  })
})
