import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Hono, type Context, type Next } from 'hono'

type TestUser = {
  userId: string
  email: string
  role: string
}

type TestEnv = {
  BUCKET_NAME: string
  IMAGES_ACCOUNT_ID: string
  MEDIA_BUCKET: {
    put: ReturnType<typeof vi.fn>
    delete: ReturnType<typeof vi.fn>
    get: ReturnType<typeof vi.fn>
  }
  DB: {
    prepare: ReturnType<typeof vi.fn>
  }
}

type AuthContext = Context & {
  set: (key: 'user', value: TestUser) => void
}

type AppContext = Context & {
  env: TestEnv
}

type UploadResponse = {
  file: {
    mimeType: string
    width: number | null
    height: number | null
    thumbnailUrl: string | null
  }
}

vi.mock('../middleware', () => ({
  requireAuth: () => async (c: Context, next: Next) => {
    ;(c as AuthContext).set('user', { userId: 'user-1', email: 'admin@test.com', role: 'admin' })
    await next()
  }
}))

import { apiMediaRoutes } from './api-media'

function createSvgFile(name = 'test.svg'): File {
  return new File(
    ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>'],
    name,
    { type: 'image/svg+xml' }
  )
}

function createMockEnv() {
  const insertBind = vi.fn().mockReturnValue({
    run: vi.fn().mockResolvedValue({ success: true })
  })
  const updateBind = vi.fn().mockReturnValue({
    run: vi.fn().mockResolvedValue({ success: true })
  })

  const env: TestEnv = {
    BUCKET_NAME: 'sonicjs-media-dev',
    IMAGES_ACCOUNT_ID: 'images-account',
    MEDIA_BUCKET: {
      put: vi.fn().mockResolvedValue({ key: 'uploads/test.svg' }),
      delete: vi.fn().mockResolvedValue(undefined),
      get: vi.fn().mockResolvedValue(null)
    },
    DB: {
      prepare: vi.fn().mockImplementation((sql: string) => {
        if (sql.includes('INSERT INTO media')) {
          return { bind: insertBind }
        }
        if (sql.includes('SELECT * FROM media WHERE id = ? AND deleted_at IS NULL')) {
          return {
            bind: vi.fn().mockReturnValue({
              first: vi.fn().mockResolvedValue({
                id: 'media-1',
                uploaded_by: 'user-1',
                folder: 'uploads'
              })
            })
          }
        }
        if (sql.includes('UPDATE media SET')) {
          return { bind: updateBind }
        }
        return {
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue(null),
            all: vi.fn().mockResolvedValue({ results: [] }),
            run: vi.fn().mockResolvedValue({ success: true })
          })
        }
      })
    }
  }

  return { env, insertBind, updateBind }
}

function createTestApp(env: TestEnv) {
  const app = new Hono()

  app.use('/api/media/*', async (c, next) => {
    ;(c as unknown as AppContext).env = env
    await next()
  })

  app.route('/api/media', apiMediaRoutes)
  return app
}

describe('apiMediaRoutes', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('stores SVG uploads with null raster metadata and no undefined bind values', async () => {
    const { env, insertBind } = createMockEnv()
    const app = createTestApp(env)
    const formData = new FormData()
    formData.append('file', createSvgFile())
    formData.append('folder', 'uploads')

    const res = await app.request('/api/media/upload', {
      method: 'POST',
      body: formData
    })

    expect(res.status).toBe(200)
    const json = await res.json() as UploadResponse
    expect(json.file.mimeType).toBe('image/svg+xml')
    expect(json.file.width).toBeNull()
    expect(json.file.height).toBeNull()
    expect(json.file.thumbnailUrl).toBeNull()

    expect(env.MEDIA_BUCKET.put).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(ArrayBuffer),
      expect.objectContaining({
        httpMetadata: expect.objectContaining({
          contentType: 'image/svg+xml'
        })
      })
    )

    const bindArgs = insertBind.mock.calls[0]
    expect(bindArgs).toBeDefined()
    expect(bindArgs.includes(undefined)).toBe(false)
    expect(bindArgs[5]).toBeNull()
    expect(bindArgs[6]).toBeNull()
    expect(bindArgs[10]).toBeNull()
  })

  it('omits undefined patch fields while preserving explicit null clears', async () => {
    const { env, updateBind } = createMockEnv()
    const app = createTestApp(env)

    const res = await app.request('/api/media/media-1', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        alt: null,
        folder: 'graphics'
      })
    })

    expect(res.status).toBe(200)

    const updateSql = env.DB.prepare.mock.calls.find(([sql]: [string]) => sql.includes('UPDATE media SET'))?.[0]
    expect(updateSql).toContain('alt = ?')
    expect(updateSql).toContain('folder = ?')
    expect(updateSql).not.toContain('caption = ?')
    expect(updateSql).not.toContain('tags = ?')

    const bindArgs = updateBind.mock.calls[0]
    expect(bindArgs).toEqual([null, 'graphics', expect.any(Number), 'media-1'])
    expect(bindArgs.includes(undefined)).toBe(false)
  })
})
