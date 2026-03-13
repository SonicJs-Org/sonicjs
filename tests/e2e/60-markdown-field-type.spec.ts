import { test, expect } from '@playwright/test'
import { loginAsAdmin, navigateToAdminSection } from './utils/test-helpers'

test.describe('Markdown Field Type', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('should initialize canonical markdown fields without TinyMCE cross-binding', async ({ page }) => {
    const collectionName = `test_markdown_${Date.now()}`
    let createdCollectionId: string | undefined

    try {
      const createCollectionResponse = await page.request.post('/admin/api/collections', {
        data: {
          name: collectionName,
          displayName: 'Markdown Field Test',
          description: 'Temporary collection for markdown editor E2E coverage',
        },
      })
      expect(createCollectionResponse.ok()).toBe(true)

      const createdCollection = await createCollectionResponse.json()
      createdCollectionId = createdCollection.id
      expect(createdCollectionId).toBeTruthy()

      const addFieldResponse = await page.request.post(`/admin/collections/${createdCollectionId}/fields`, {
        form: {
          field_name: 'body',
          field_type: 'markdown',
          field_label: 'Body',
          field_options: JSON.stringify({ toolbar: 'full', height: 400 }),
          is_required: '1',
        },
      })
      expect(addFieldResponse.ok()).toBe(true)

      const addFieldResult = await addFieldResponse.json()
      expect(addFieldResult.success).toBe(true)

      await navigateToAdminSection(page, 'content')
      await page.goto(`/admin/content/new?collection=${createdCollectionId}`)

      await expect(page.locator('input[name="title"]')).toBeVisible({ timeout: 10000 })

      const easyMdeRichtextContainer = page.locator('.richtext-container[data-editor-provider="easymde"]').first()
      const easyMdeRichtextContainerCount = await easyMdeRichtextContainer.count()
      const fallbackWarning = page.locator('text=Markdown editor plugin is inactive').first()
      let markdownTextarea = page.locator('textarea[name="body"]').first()

      if (easyMdeRichtextContainerCount > 0) {
        await expect(easyMdeRichtextContainer).toBeVisible()
        markdownTextarea = easyMdeRichtextContainer.locator('textarea[name="body"]').first()

        const easyMdeContainer = page.locator('.EasyMDEContainer').first()
        await expect(easyMdeContainer).toBeVisible({ timeout: 10000 })
      } else {
        await expect(fallbackWarning).toBeVisible()
      }

      await expect(markdownTextarea).toBeVisible()

      const editorBindingState = await page.evaluate(() => {
        const browserWindow = window as Window & {
          tinymce?: { get: (id: string) => unknown }
        }
        const markdown = document.querySelector('textarea[name="body"]') as HTMLTextAreaElement & {
          easyMDEInstance?: { value: (nextValue?: string) => string }
        }

        if (!markdown) {
          throw new Error('Expected markdown textarea was not found')
        }

        return {
          markdownId: markdown.id,
          markdownHasEasyMde: Boolean(markdown.easyMDEInstance),
          markdownHasTinyMce: typeof browserWindow.tinymce !== 'undefined' && Boolean(browserWindow.tinymce.get(markdown.id)),
        }
      })

      expect(editorBindingState.markdownHasTinyMce).toBe(false)

      if (editorBindingState.markdownHasEasyMde) {
        await page.evaluate(() => {
          const textarea = document.querySelector('textarea[name="body"]') as HTMLTextAreaElement & {
            easyMDEInstance?: { value: (nextValue?: string) => string }
          }

          if (!textarea?.easyMDEInstance) {
            throw new Error('EasyMDE instance not found on markdown textarea')
          }

          textarea.easyMDEInstance.value('# Markdown Title\n\nCanonical markdown field content.')
        })
      } else {
        await markdownTextarea.fill('# Markdown Title\n\nCanonical markdown field content.')
      }

      await expect(markdownTextarea).toHaveValue('# Markdown Title\n\nCanonical markdown field content.')
    } finally {
      if (createdCollectionId) {
        await page.request.fetch(`/admin/api/collections/${createdCollectionId}`, {
          method: 'DELETE',
        })
      }
    }
  })
})
