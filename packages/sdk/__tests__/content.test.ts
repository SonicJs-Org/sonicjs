import { describe, it, expect, vi } from 'vitest'
import { createClient } from '../src/client'
import type { ListResponse, ItemResponse, ContentRecord } from '../src/types'

function mockFetch(body: unknown, status = 200, headers?: Record<string, string>) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    text: () => Promise.resolve(JSON.stringify(body)),
    headers: new Headers(headers),
  } as Response)
}

function makeClient(fetchFn: ReturnType<typeof vi.fn>) {
  return createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })
}

const record: ContentRecord = {
  id: '1',
  title: 'Hello',
  slug: 'hello',
  status: 'published',
  collectionId: 'posts',
  data: { body: 'World' },
  created_at: 1700000000000,
  updated_at: 1700000001000,
}

describe('ContentResource', () => {
  it('list — GET /api/content with no options', async () => {
    const fetch = mockFetch({ data: [record], meta: { count: 1, timestamp: '' } })
    const sonic = makeClient(fetch)
    const res = await sonic.content.list()
    expect(res.data).toHaveLength(1)
    expect(fetch).toHaveBeenCalledOnce()
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://cms.test/api/content')
    expect(init.method).toBe('GET')
  })

  it('list — serializes where/sort/limit options', async () => {
    const fetch = mockFetch({ data: [], meta: { count: 0, timestamp: '' } })
    const sonic = makeClient(fetch)
    await sonic.content.list({
      limit: 10,
      offset: 20,
      status: 'published',
      sort: 'created_at',
      dir: 'desc',
      where: { collectionId: { equals: 'posts' } },
    })
    const [url] = fetch.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('limit=10')
    expect(url).toContain('offset=20')
    expect(url).toContain('status=published')
    expect(url).toContain('sort=created_at')
    expect(url).toContain('dir=desc')
    expect(url).toContain('where%5BcollectionId%5D%5Bequals%5D=posts')
  })

  it('list — fields array serialized as CSV', async () => {
    const fetch = mockFetch({ data: [], meta: { count: 0, timestamp: '' } })
    const sonic = makeClient(fetch)
    await sonic.content.list({ fields: ['id', 'title', 'data.excerpt'] })
    const [url] = fetch.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('fields=id%2Ctitle%2Cdata.excerpt')
  })

  it('list — sends api key header', async () => {
    const fetch = mockFetch({ data: [], meta: { count: 0, timestamp: '' } })
    const sonic = createClient({ url: 'https://cms.test', apiKey: 'sk_abc', fetch: fetch as typeof fetch })
    await sonic.content.list()
    const [, init] = fetch.mock.calls[0] as [string, RequestInit]
    expect((init.headers as Record<string, string>)['x-api-key']).toBe('sk_abc')
  })

  it('get — GET /api/content/:id', async () => {
    const fetch = mockFetch({ data: record })
    const sonic = makeClient(fetch)
    const res = await sonic.content.get('abc-123')
    expect(res.data.id).toBe('1')
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('/api/content/abc-123')
    expect(init.method).toBe('GET')
  })

  it('create — POST with JSON body', async () => {
    const fetch = mockFetch({ data: record }, 201)
    const sonic = makeClient(fetch)
    await sonic.content.create({ collectionId: 'posts', title: 'New Post', data: { body: 'Hi' } })
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://cms.test/api/content')
    expect(init.method).toBe('POST')
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
    const body = JSON.parse(init.body as string)
    expect(body.collectionId).toBe('posts')
    expect(body.title).toBe('New Post')
  })

  it('update — PUT /api/content/:id', async () => {
    const fetch = mockFetch({ data: record })
    const sonic = makeClient(fetch)
    await sonic.content.update('abc', { title: 'Updated' })
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('/api/content/abc')
    expect(init.method).toBe('PUT')
  })

  it('delete — DELETE /api/content/:id', async () => {
    const fetch = mockFetch({ success: true })
    const sonic = makeClient(fetch)
    const res = await sonic.content.delete('abc')
    expect(res.success).toBe(true)
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('/api/content/abc')
    expect(init.method).toBe('DELETE')
  })

  it('non-2xx throws SonicError with status + message', async () => {
    const { SonicError } = await import('../src/errors')
    const fetch = mockFetch({ error: 'Not found', details: 'missing' }, 404)
    const sonic = makeClient(fetch)
    await expect(sonic.content.get('nope')).rejects.toThrow(SonicError)
    await expect(sonic.content.get('nope')).rejects.toMatchObject({ status: 404, code: 'http_error', message: 'Not found' })
  })
})
