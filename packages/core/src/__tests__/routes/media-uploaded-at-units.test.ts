/**
 * Regression test: media `uploaded_at` is stored in milliseconds
 *
 * Uploads used to store `uploaded_at` as epoch SECONDS
 * (Math.floor(Date.now()/1000)) while the admin renderers read it as epoch
 * MILLISECONDS (new Date(uploaded_at)), so new uploads displayed as Jan 1970
 * and sorted to the bottom. The upload routes now store Date.now() (ms), and
 * the API JSON readers no longer multiply by 1000.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'

vi.mock('../../middleware', () => ({
  requireAuth: () => async (c: any, next: any) => {
    c.set('user', { userId: 'u1', id: 'u1', email: 'admin@test.com', role: 'admin' })
    await next()
  },
  requireRole: () => async (_c: any, next: any) => {
    await next()
  },
}))

import apiMediaRoutes from '../../routes/api-media'
import { adminMediaRoutes } from '../../routes/admin-media'

// Anything past this is milliseconds; below it is the old seconds bug (~1973).
const MS_THRESHOLD = 100_000_000_000

function pngFile() {
  return new File([new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])], 'test.png', {
    type: 'image/png',
  })
}

/** Mock env that records the params bound to the INSERT INTO media statement. */
function createUploadEnv(extraRows: any[] = []) {
  const inserts: unknown[][] = []
  const db = {
    prepare: vi.fn((sql: string) => {
      const statement: any = {
        bind: vi.fn((...params: unknown[]) => {
          if (sql.includes('INSERT INTO media')) inserts.push(params)
          return statement
        }),
        run: vi.fn(async () => ({})),
        all: vi.fn(async () => ({ results: extraRows })),
        first: vi.fn(async () => null),
      }
      return statement
    }),
  }
  const env = {
    DB: db,
    KV: {},
    MEDIA_BUCKET: { put: vi.fn(async () => ({ key: 'ok' })) },
  }
  return { env, inserts }
}

/** uploaded_at is the 13th (last) bound column in the media INSERT. */
const uploadedAtOf = (params: unknown[]) => params[12] as number

describe('media uploaded_at is stored in milliseconds', () => {
  const thisYear = new Date().getUTCFullYear()

  describe('POST /api/media/upload', () => {
    let app: Hono
    beforeEach(() => {
      vi.clearAllMocks()
      app = new Hono()
      app.route('/api/media', apiMediaRoutes)
    })

    it('stores ms and returns a current-year ISO date', async () => {
      const { env, inserts } = createUploadEnv()
      const fd = new FormData()
      fd.append('file', pngFile())

      const res = await app.fetch(
        new Request('https://test.com/api/media/upload', { method: 'POST', body: fd }),
        env as any
      )
      expect(res.status).toBe(200)
      const json = (await res.json()) as any
      expect(json.success).toBe(true)

      // Stored value is millisecond-magnitude.
      expect(inserts).toHaveLength(1)
      expect(uploadedAtOf(inserts[0])).toBeGreaterThan(MS_THRESHOLD)

      // API JSON date is correct (no longer 1970, no double ×1000).
      expect(new Date(json.file.uploadedAt).getUTCFullYear()).toBe(thisYear)
    })
  })

  describe('POST /api/media/upload-multiple', () => {
    let app: Hono
    beforeEach(() => {
      vi.clearAllMocks()
      app = new Hono()
      app.route('/api/media', apiMediaRoutes)
    })

    it('stores ms for each file', async () => {
      const { env, inserts } = createUploadEnv()
      const fd = new FormData()
      fd.append('files', pngFile())
      fd.append('files', pngFile())

      const res = await app.fetch(
        new Request('https://test.com/api/media/upload-multiple', { method: 'POST', body: fd }),
        env as any
      )
      expect(res.status).toBe(200)
      const json = (await res.json()) as any

      expect(inserts).toHaveLength(2)
      for (const params of inserts) {
        expect(uploadedAtOf(params)).toBeGreaterThan(MS_THRESHOLD)
      }
      expect(new Date(json.uploaded[0].uploadedAt).getUTCFullYear()).toBe(thisYear)
    })
  })

  describe('POST /admin/media/upload', () => {
    let app: Hono
    beforeEach(() => {
      vi.clearAllMocks()
      app = new Hono()
      app.route('/admin/media', adminMediaRoutes)
    })

    it('stores ms for the admin upload route', async () => {
      // The handler re-queries the grid after upload; give it one row back.
      const gridRow = {
        id: 'g1',
        filename: 'g1.png',
        original_name: 'g1.png',
        mime_type: 'image/png',
        size: 10,
        r2_key: 'uploads/g1.png',
        tags: null,
        uploaded_at: Date.now(),
      }
      const { env, inserts } = createUploadEnv([gridRow])
      const fd = new FormData()
      fd.append('files', pngFile())

      const res = await app.fetch(
        new Request('https://test.com/admin/media/upload', { method: 'POST', body: fd }),
        env as any
      )
      expect(res.status).toBe(200)

      expect(inserts).toHaveLength(1)
      expect(uploadedAtOf(inserts[0])).toBeGreaterThan(MS_THRESHOLD)
    })
  })
})
