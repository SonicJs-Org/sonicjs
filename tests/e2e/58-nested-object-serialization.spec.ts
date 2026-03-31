import { expect, test } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

async function resolvePageBlocksCollectionKey(page: import('@playwright/test').Page): Promise<string | null> {
  await page.goto('/admin/content/new')
  await page.waitForLoadState('networkidle', { timeout: 15000 })

  const pageBlocksLink = page
    .locator('a[href^="/admin/content/new?collection="]')
    .filter({ hasText: 'Page Blocks' })
    .first()

  if (!(await pageBlocksLink.isVisible({ timeout: 5000 }).catch(() => false))) {
    return null
  }

  const href = await pageBlocksLink.getAttribute('href')
  const match = href?.match(/[?&]collection=([^&]+)/)
  return match?.[1] || null
}

test.describe('Nested Object Serialization', () => {
  test('should persist sibling flat child objects inside a nested parent object', async ({ page }) => {
    await loginAsAdmin(page)

    const collectionKey = await resolvePageBlocksCollectionKey(page)
    test.skip(!collectionKey, 'Page Blocks collection not available')

    await page.goto('/admin/content/new?collection=' + encodeURIComponent(collectionKey!))
    await page.waitForLoadState('networkidle')
    await expect(page.locator('form#content-form')).toBeVisible()

    await page.fill('input[name="title"]', 'Opening Hours Serialization Test')
    await page.fill('input[name="slug"]', 'opening-hours-serialization-test')

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

    await page.click('button[name="action"][value="save_and_publish"]')
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
    await page.click('button[name="action"][value="save_and_publish"]')
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
