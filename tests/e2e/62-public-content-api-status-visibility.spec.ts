import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Public Content API Status Visibility', () => {
  let authCookie = ''
  let collectionId = ''
  let collectionName = ''
  let publishedContentId = ''
  let draftContentId = ''
  let publishedSlug = ''
  let draftSlug = ''

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext()
    const page = await context.newPage()

    await loginAsAdmin(page)

    const cookies = await context.cookies()
    const sessionCookie = cookies.find(cookie => cookie.name.includes('session') || cookie.name.includes('auth'))
    authCookie = sessionCookie ? `${sessionCookie.name}=${sessionCookie.value}` : ''

    const collectionsResponse = await page.request.get('/api/collections')
    expect(collectionsResponse.ok()).toBeTruthy()

    const collectionsData = await collectionsResponse.json()
    const pagesCollection = collectionsData.data.find((collection: any) => collection.name === 'pages') || collectionsData.data[0]

    expect(pagesCollection).toBeDefined()

    collectionId = pagesCollection.id
    collectionName = pagesCollection.name

    const uniqueSuffix = `${Date.now()}`
    publishedSlug = `public-api-published-${uniqueSuffix}`
    draftSlug = `public-api-draft-${uniqueSuffix}`

    const publishedResponse = await page.request.post('/api/content', {
      data: {
        collectionId,
        title: `Public API Published ${uniqueSuffix}`,
        slug: publishedSlug,
        status: 'published',
        data: {
          content: 'Published content for public API visibility tests'
        }
      }
    })

    expect(publishedResponse.status()).toBe(201)
    const publishedData = await publishedResponse.json()
    publishedContentId = publishedData.data.id

    const draftResponse = await page.request.post('/api/content', {
      data: {
        collectionId,
        title: `Public API Draft ${uniqueSuffix}`,
        slug: draftSlug,
        status: 'draft',
        data: {
          content: 'Draft content for public API visibility tests'
        }
      }
    })

    expect(draftResponse.status()).toBe(201)
    const draftData = await draftResponse.json()
    draftContentId = draftData.data.id

    await context.close()
  })

  test.afterAll(async ({ browser }) => {
    if (!authCookie) {
      return
    }

    const context = await browser.newContext()
    const page = await context.newPage()

    for (const contentId of [publishedContentId, draftContentId]) {
      if (!contentId) {
        continue
      }

      await page.request.delete(`/api/content/${contentId}`, {
        headers: {
          Cookie: authCookie
        }
      })
    }

    await context.close()
  })

  test('should force published-only results for anonymous /api/content requests', async ({ request }) => {
    const where = encodeURIComponent(JSON.stringify({
      or: [
        { field: 'status', operator: 'not_equals', value: 'published' },
        { field: 'slug', operator: 'equals', value: publishedSlug },
        { field: 'slug', operator: 'equals', value: draftSlug }
      ]
    }))

    const response = await request.get(`/api/content?collection=${collectionName}&where=${where}&limit=100`)

    expect(response.ok()).toBeTruthy()

    const data = await response.json()
    const slugs = data.data.map((item: any) => item.slug)

    expect(slugs).toContain(publishedSlug)
    expect(slugs).not.toContain(draftSlug)
    expect(data.data.every((item: any) => item.status === 'published')).toBeTruthy()
    expect(data.meta.filter.where.and).toContainEqual({
      field: 'status',
      operator: 'equals',
      value: 'published'
    })
  })

  test('should force published-only results for anonymous collection-specific requests', async ({ request }) => {
    const response = await request.get(`/api/collections/${collectionName}/content?status=draft&limit=100`)

    expect(response.ok()).toBeTruthy()

    const data = await response.json()
    const slugs = data.data.map((item: any) => item.slug)

    expect(slugs).toContain(publishedSlug)
    expect(slugs).not.toContain(draftSlug)
    expect(data.data.every((item: any) => item.status === 'published')).toBeTruthy()
    expect(data.meta.filter.where.and).toContainEqual({
      field: 'status',
      operator: 'equals',
      value: 'published'
    })
  })

  test('should allow authenticated callers to request draft content explicitly', async ({ request }) => {
    const response = await request.get(`/api/content?collection=${collectionName}&status=draft&limit=100`, {
      headers: {
        Cookie: authCookie
      }
    })

    expect(response.ok()).toBeTruthy()

    const data = await response.json()
    const slugs = data.data.map((item: any) => item.slug)

    expect(slugs).toContain(draftSlug)
    expect(data.data.every((item: any) => item.status === 'draft')).toBeTruthy()
  })
})
