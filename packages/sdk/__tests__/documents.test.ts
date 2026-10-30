import { describe, it, expect, vi } from 'vitest'
import { createClient } from '../src/client'
import type { DocumentRow } from '../src/types'

function makeDoc(id: string): DocumentRow {
  return {
    id,
    rootId: id,
    typeId: 'blog_posts',
    title: `Post ${id}`,
    slug: `post-${id}`,
    path: null,
    locale: 'default',
    publishedAt: 1700000,
    updatedAt: 1700001,
    data: {},
  }
}

function mockPage(docs: DocumentRow[], nextCursor: { cursor_updated_at: number; cursor_id: string } | null) {
  return {
    data: docs,
    pagination: { limit: docs.length, nextCursor },
  }
}

function makeFetchSequence(responses: unknown[]) {
  let call = 0
  return vi.fn().mockImplementation(() => {
    const body = responses[call++ % responses.length]
    return Promise.resolve({
      ok: true,
      status: 200,
      statusText: 'OK',
      text: () => Promise.resolve(JSON.stringify(body)),
      headers: new Headers(),
    } as Response)
  })
}

describe('DocumentsResource', () => {
  it('list — GET /api/documents with type', async () => {
    const fetchFn = makeFetchSequence([mockPage([makeDoc('1')], null)])
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })
    const page = await sonic.documents.list({ type: 'blog_posts' })
    expect(page.data).toHaveLength(1)
    expect(page.nextCursor).toBeNull()
    const [url] = fetchFn.mock.calls[0] as [string]
    expect(url).toContain('/api/documents')
    expect(url).toContain('type=blog_posts')
  })

  it('list — maps cursor_updated_at/cursor_id to KeysetCursor', async () => {
    const fetchFn = makeFetchSequence([
      mockPage([makeDoc('1')], { cursor_updated_at: 1700001, cursor_id: 'abc' }),
    ])
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })
    const page = await sonic.documents.list({ type: 'blog_posts' })
    expect(page.nextCursor).toEqual({ updatedAt: 1700001, id: 'abc' })
  })

  it('list — passes cursor as cursor_updated_at + cursor_id params', async () => {
    const fetchFn = makeFetchSequence([mockPage([], null)])
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })
    await sonic.documents.list({ type: 'blog_posts', cursor: { updatedAt: 1700001, id: 'abc' } })
    const [url] = fetchFn.mock.calls[0] as [string]
    expect(url).toContain('cursor_updated_at=1700001')
    expect(url).toContain('cursor_id=abc')
  })

  it('iterate — follows nextCursor across pages then stops', async () => {
    const page1 = mockPage([makeDoc('1'), makeDoc('2')], { cursor_updated_at: 1700002, cursor_id: 'c2' })
    const page2 = mockPage([makeDoc('3')], null)
    const fetchFn = makeFetchSequence([page1, page2])
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })

    const docs: DocumentRow[] = []
    for await (const doc of sonic.documents.iterate({ type: 'blog_posts', limit: 2 })) {
      docs.push(doc)
    }

    expect(docs).toHaveLength(3)
    expect(docs.map((d) => d.id)).toEqual(['1', '2', '3'])
    expect(fetchFn).toHaveBeenCalledTimes(2)
  })

  it('iterate — single page with no cursor terminates immediately', async () => {
    const fetchFn = makeFetchSequence([mockPage([makeDoc('1')], null)])
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })

    const docs: DocumentRow[] = []
    for await (const doc of sonic.documents.iterate({ type: 'blog_posts' })) {
      docs.push(doc)
    }
    expect(docs).toHaveLength(1)
    expect(fetchFn).toHaveBeenCalledTimes(1)
  })

  it('getByRoot — GET /api/documents/root/:rootId', async () => {
    const doc = makeDoc('root-1')
    const fetchFn = makeFetchSequence([doc])
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })
    const result = await sonic.documents.getByRoot('root-1')
    expect(result.id).toBe('root-1')
    const [url] = fetchFn.mock.calls[0] as [string]
    expect(url).toContain('/api/documents/root/root-1')
  })

  it('get — GET /api/documents/:id', async () => {
    const doc = makeDoc('rev-42')
    const fetchFn = makeFetchSequence([doc])
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })
    await sonic.documents.get('rev-42')
    const [url] = fetchFn.mock.calls[0] as [string]
    expect(url).toContain('/api/documents/rev-42')
  })
})
