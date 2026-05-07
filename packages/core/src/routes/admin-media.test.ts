import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Hono, type Context, type Next } from 'hono'

type TestUser = {
  userId: string
  email: string
  role: string
}

type TestEnv = {
  MEDIA_BUCKET: {
    put: ReturnType<typeof vi.fn>
    get: ReturnType<typeof vi.fn>
    delete: ReturnType<typeof vi.fn>
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
  set: (key: 'appVersion', value: string) => void
}

vi.mock('../middleware', () => ({
  requireAuth: () => async (c: Context, next: Next) => {
    ;(c as AuthContext).set('user', { userId: 'user-1', email: 'admin@test.com', role: 'admin' })
    await next()
  },
  requireRole: () => async (_c: Context, next: Next) => {
    await next()
  }
}))

vi.mock('../templates/pages/admin-media-library.template', () => ({
  renderMediaLibraryPage: () => '<html></html>'
}))

vi.mock('../templates/components/media-file-details.template', () => ({
  renderMediaFileDetails: () => '<div></div>'
}))

vi.mock('../templates/components/media-grid.template', () => ({
  renderMediaFileCard: () => '<div></div>'
}))

import { adminMediaRoutes } from './admin-media'

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
    MEDIA_BUCKET: {
      put: vi.fn().mockResolvedValue({ key: 'uploads/test.svg' }),
      get: vi.fn().mockResolvedValue(null),
      delete: vi.fn().mockResolvedValue(undefined)
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
                uploaded_by: 'user-1'
              })
            })
          }
        }
        if (sql.includes('UPDATE media')) {
          return { bind: updateBind }
        }
        return {
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue(null),
            all: vi.fn().mockResolvedValue({ results: [] }),
            run: vi.fn().mockResolvedValue({ success: true })
          }),
          all: vi.fn().mockResolvedValue({ results: [] })
        }
      })
    }
  }

  return { env, insertBind, updateBind }
}

function createTestApp(env: TestEnv) {
  const app = new Hono()

  app.use('/admin/media/*', async (c, next) => {
    const appContext = c as unknown as AppContext
    appContext.env = env
    appContext.set('appVersion', '2.0.0')
    await next()
  })

  app.route('/admin/media', adminMediaRoutes)
  return app
}

describe('adminMediaRoutes', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('stores SVG uploads with null raster metadata and no undefined bind values', async () => {
    const { env, insertBind } = createMockEnv()
    const app = createTestApp(env)
    const formData = new FormData()
    formData.append('files', createSvgFile())
    formData.append('folder', 'uploads')

    const res = await app.request('/admin/media/upload', {
      method: 'POST',
      body: formData
    })

    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain('Successfully uploaded 1 file')

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
    expect(bindArgs.includes(undefined)).toBe(false)
    expect(bindArgs[5]).toBeNull()
    expect(bindArgs[6]).toBeNull()
    expect(bindArgs[10]).toBeNull()
  })

  it('updates only provided metadata fields and never binds undefined', async () => {
    const { env, updateBind } = createMockEnv()
    const app = createTestApp(env)
    const formData = new FormData()
    formData.append('alt', '')

    const res = await app.request('/admin/media/media-1', {
      method: 'PUT',
      body: formData
    })

    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain('File updated successfully')

    const updateSql = env.DB.prepare.mock.calls.find(([sql]: [string]) => sql.includes('UPDATE media'))?.[0]
    expect(updateSql).toContain('alt = ?')
    expect(updateSql).not.toContain('caption = ?')
    expect(updateSql).not.toContain('tags = ?')

    const bindArgs = updateBind.mock.calls[0]
    expect(bindArgs).toEqual([null, expect.any(Number), 'media-1'])
    expect(bindArgs.includes(undefined)).toBe(false)
  })
})
