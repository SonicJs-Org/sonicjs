import { describe, it, expect, vi } from 'vitest'
import { createClient } from '../src/client'
import type { MediaAsset } from '../src/types'

const asset: MediaAsset = {
  id: 'media-1',
  filename: 'photo.jpg',
  originalName: 'photo.jpg',
  mimeType: 'image/jpeg',
  size: 12345,
  publicUrl: 'https://r2.example.com/photo.jpg',
  thumbnailUrl: null,
  uploadedAt: '2024-01-01T00:00:00Z',
}

function mockFetch(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: 'OK',
    text: () => Promise.resolve(JSON.stringify(body)),
    headers: new Headers(),
  } as Response)
}

describe('MediaResource', () => {
  it('upload — POST /api/media/upload with FormData (no manual Content-Type)', async () => {
    const fetchFn = mockFetch({ success: true, file: asset })
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })

    const blob = new Blob(['data'], { type: 'image/jpeg' })
    await sonic.media.upload(blob, { folder: 'avatars' })

    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://cms.test/api/media/upload')
    expect(init.method).toBe('POST')
    expect(init.body).toBeInstanceOf(FormData)
    // Must NOT manually set Content-Type (browser sets multipart boundary)
    expect((init.headers as Record<string, string>)?.['Content-Type']).toBeUndefined()
  })

  it('upload — appends folder to FormData', async () => {
    const fetchFn = mockFetch({ success: true, file: asset })
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })

    const blob = new Blob(['data'])
    await sonic.media.upload(blob, { folder: 'profile-pics' })

    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit]
    const fd = init.body as FormData
    expect(fd.get('folder')).toBe('profile-pics')
  })

  it('uploadMany — POST /api/media/upload-multiple', async () => {
    const fetchFn = mockFetch({
      success: true,
      uploaded: [asset],
      errors: [],
      summary: { total: 1, successful: 1, failed: 0 },
    })
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })

    const blobs = [new Blob(['a']), new Blob(['b'])]
    const res = await sonic.media.uploadMany(blobs)

    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://cms.test/api/media/upload-multiple')
    expect(init.method).toBe('POST')
    expect(res.summary.total).toBe(1)
  })

  it('bulkDelete — POST /api/media/bulk-delete with JSON body', async () => {
    const fetchFn = mockFetch({ success: true, deleted: ['media-1', 'media-2'], errors: [] })
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })

    await sonic.media.bulkDelete(['media-1', 'media-2'])

    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://cms.test/api/media/bulk-delete')
    expect(init.method).toBe('POST')
    const body = JSON.parse(init.body as string)
    expect(body.fileIds).toEqual(['media-1', 'media-2'])
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
  })

  it('upload — requires auth header when apiKey provided', async () => {
    const fetchFn = mockFetch({ success: true, file: asset })
    const sonic = createClient({ url: 'https://cms.test', apiKey: 'sk_test', fetch: fetchFn as typeof fetch })

    await sonic.media.upload(new Blob(['x']))
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit]
    expect((init.headers as Record<string, string>)['x-api-key']).toBe('sk_test')
  })
})
