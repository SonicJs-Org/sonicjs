import { test, expect } from '@playwright/test'

test.describe('default content seed', () => {
  test('exposes the code-defined blog_post collection without legacy defaults', async ({ request }) => {
    const response = await request.get('/api/collections')
    expect(response.ok()).toBeTruthy()

    const body = await response.json()
    const collections = body.data ?? []
    const names = collections.map((collection: any) => collection.name)
    expect(names).toContain('blog_post')
    expect(names).not.toContain('pages')
    expect(names).not.toContain('news')
    expect(names).not.toContain('contact_messages')
    expect(names).not.toContain('page_blocks')
  })

  test('seeds one published welcome blog post', async ({ request }) => {
    const response = await request.get('/api/documents?type=blog_post&limit=100')
    expect(response.ok()).toBeTruthy()

    const body = await response.json()
    const posts = body.data ?? []
    const welcomePosts = posts.filter((post: any) => post.slug === 'welcome-to-sonicjs')
    expect(welcomePosts).toHaveLength(1)
    expect(welcomePosts[0]).toMatchObject({
      typeId: 'blog_post',
      title: 'Welcome to SonicJS',
      slug: 'welcome-to-sonicjs',
    })
  })
})
