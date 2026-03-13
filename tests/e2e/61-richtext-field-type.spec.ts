import { expect, test, type Page } from '@playwright/test'
import { loginAsAdmin, navigateToAdminSection } from './utils/test-helpers'

async function createTestCollection(page: Page, suffix: string) {
  const createCollectionResponse = await page.request.post('/admin/api/collections', {
    data: {
      name: `test_${suffix}_${Date.now()}`,
      displayName: `${suffix} Field Test`,
      description: `Temporary collection for ${suffix} field E2E coverage`,
    },
  })
  expect(createCollectionResponse.ok()).toBe(true)

  const createdCollection = await createCollectionResponse.json()
  expect(createdCollection.id).toBeTruthy()
  return createdCollection.id as string
}

test.describe('Richtext Field Type', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('should render richtext fields created through the collection editor via the richtext path', async ({
    page,
  }) => {
    let createdCollectionId: string | undefined

    try {
      createdCollectionId = await createTestCollection(page, 'richtext')

      const addFieldResponse = await page.request.post(`/admin/collections/${createdCollectionId}/fields`, {
        form: {
          field_name: 'body',
          field_type: 'richtext',
          field_label: 'Body',
          field_options: JSON.stringify({ toolbar: 'minimal', height: 250 }),
          is_required: '1',
        },
      })
      expect(addFieldResponse.ok()).toBe(true)

      const addFieldResult = await addFieldResponse.json()
      expect(addFieldResult.success).toBe(true)

      await navigateToAdminSection(page, 'content')
      await page.goto(`/admin/content/new?collection=${createdCollectionId}`)

      await expect(page.locator('input[name="title"]')).toBeVisible({ timeout: 10000 })

      await expect(page.locator('input[type="text"][name="body"]')).toHaveCount(0)

      const richtextContainer = page.locator('.richtext-container[data-editor-provider="tinymce"]').first()
      const richtextContainerCount = await richtextContainer.count()
      const fallbackWarning = page.locator('text=TinyMCE plugin is inactive').first()

      let richtextTextarea = page.locator('textarea[name="body"]').first()

      if (richtextContainerCount > 0) {
        await expect(richtextContainer).toBeVisible()
        richtextTextarea = richtextContainer.locator('textarea[name="body"]').first()
      } else {
        await expect(fallbackWarning).toBeVisible()
      }

      await expect(richtextTextarea).toBeVisible()

      const editorBindingState = await page.evaluate(() => {
        const textarea = document.querySelector('textarea[name="body"]') as HTMLTextAreaElement & {
          easyMDEInstance?: unknown
        }

        if (!textarea) {
          throw new Error('Expected richtext textarea was not found')
        }

        return {
          hasEasyMde: Boolean(textarea.easyMDEInstance),
          tagName: textarea.tagName.toLowerCase(),
        }
      })

      expect(editorBindingState.tagName).toBe('textarea')
      expect(editorBindingState.hasEasyMde).toBe(false)
    } finally {
      if (createdCollectionId) {
        await page.request.fetch(`/admin/api/collections/${createdCollectionId}`, {
          method: 'DELETE',
        })
      }
    }
  })

  test('should preserve options for select fields created through the collection editor', async ({ page }) => {
    let createdCollectionId: string | undefined

    try {
      createdCollectionId = await createTestCollection(page, 'select')

      const addFieldResponse = await page.request.post(`/admin/collections/${createdCollectionId}/fields`, {
        form: {
          field_name: 'audience',
          field_type: 'select',
          field_label: 'Audience',
          field_options: JSON.stringify({
            options: ['draft', 'published'],
            multiple: false,
          }),
          is_required: '1',
        },
      })
      expect(addFieldResponse.ok()).toBe(true)

      const addFieldResult = await addFieldResponse.json()
      expect(addFieldResult.success).toBe(true)

      await navigateToAdminSection(page, 'content')
      await page.goto(`/admin/content/new?collection=${createdCollectionId}`)

      const statusSelect = page.locator('select[name="audience"]').first()
      await expect(statusSelect).toBeVisible({ timeout: 10000 })
      await expect(statusSelect.locator('option')).toHaveCount(2)
      await expect(statusSelect.locator('option[value="draft"]')).toHaveText('draft')
      await expect(statusSelect.locator('option[value="published"]')).toHaveText('published')

      await statusSelect.selectOption('published')
      await expect(statusSelect).toHaveValue('published')
    } finally {
      if (createdCollectionId) {
        await page.request.fetch(`/admin/api/collections/${createdCollectionId}`, {
          method: 'DELETE',
        })
      }
    }
  })
})
