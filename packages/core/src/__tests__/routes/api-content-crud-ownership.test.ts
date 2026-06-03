import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'

/**
 * Integration tests for `own`-scope enforcement on the JSON content API
 * (PUT/DELETE /api/content/:id).
 *
 * This is the part the service-level unit tests can't cover: that the route
 * handlers actually *block* on the resolved scope. With `own` scope a user must
 * only be able to mutate records they authored; with `any` ownership is
 * irrelevant. A regression here is a horizontal-privilege-escalation bug
 * (editing another author's content), so it's worth testing through the real
 * route rather than the helper in isolation.
 *
 * RbacService is mocked to control the resolved scope; the route's real
 * ownership comparison (`author_id === user.userId`) and cache calls run for
 * real against a fake D1.
 */

// `can()` gates the route (requireRbac); `getPermissionScope()` drives the
// fine-grained own/any decision inside the handler. Both are mocked here.
const mockCan = vi.fn()
const mockGetPermissionScope = vi.fn()

vi.mock('../../services/rbac', () => ({
  RbacService: class {
    can = mockCan
    getPermissionScope = mockGetPermissionScope
  },
}))

// eslint-disable-next-line import/first
import apiContentCrudRoutes from '../../routes/api-content-crud'

type AuthUser = { userId: string; email: string; role: string }

const OWNER = 'author-owner'
const OTHER = 'author-other'

const editor: AuthUser = { userId: OWNER, email: 'owner@test.com', role: 'editor' }

/** A content row as returned by the handlers' existence queries. */
function contentRow(authorId: string) {
  return {
    id: 'post-1',
    collection_id: 'col-blog',
    collection_name: 'blog_posts',
    author_id: authorId,
    title: 'Hello',
    slug: 'hello',
    status: 'draft',
    data: '{}',
    created_at: 1,
    updated_at: 1,
  }
}

/**
 * Fake D1 keyed by SQL shape. The existence query (JOINs collections) returns
 * `existing` (or null to simulate 404); the final `SELECT * FROM content`
 * returns the post-mutation row; UPDATE/DELETE just succeed.
 */
function makeDb(existing: Record<string, unknown> | null) {
  return {
    prepare: (sql: string) => ({
      bind: (..._params: unknown[]) => ({
        first: async () => {
          if (sql.includes('JOIN collections')) return existing
          if (/^\s*SELECT \* FROM content WHERE id/.test(sql)) {
            return existing ? { ...existing, title: 'Hello (updated)' } : null
          }
          return null
        },
        run: async () => ({ success: true }),
      }),
    }),
  }
}

function buildApp(user: AuthUser | undefined, existing: Record<string, unknown> | null) {
  const app = new Hono()
  const DB = makeDb(existing)
  app.use('*', async (c, next) => {
    if (user) c.set('user', user as any)
    await next()
  })
  app.route('/api/content', apiContentCrudRoutes)
  const req = (method: 'PUT' | 'DELETE', body?: unknown) =>
    app.request(
      '/api/content/post-1',
      {
        method,
        headers: { 'Content-Type': 'application/json' },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      },
      { DB } as any
    )
  return { req }
}

describe('content API ownership enforcement (own scope)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // By default the coarse RBAC gate (requireRbac) allows the verb; the
    // handler's scope check is what each test actually exercises.
    mockCan.mockResolvedValue(true)
  })

  describe('PUT /api/content/:id', () => {
    it('allows an own-scoped author to update their own record', async () => {
      mockGetPermissionScope.mockResolvedValue('own')
      const { req } = buildApp(editor, contentRow(OWNER))

      const res = await req('PUT', { title: 'Hello (updated)' })
      expect(res.status).toBe(200)
      const body = await res.json()
      expect(body.data.title).toBe('Hello (updated)')
    })

    it("blocks an own-scoped author from updating another author's record", async () => {
      mockGetPermissionScope.mockResolvedValue('own')
      const { req } = buildApp(editor, contentRow(OTHER))

      const res = await req('PUT', { title: 'hijack' })
      expect(res.status).toBe(403)
      expect(await res.json()).toEqual({ error: 'Insufficient permissions' })
    })

    it('allows an any-scoped user to update any record regardless of author', async () => {
      mockGetPermissionScope.mockResolvedValue('any')
      const { req } = buildApp(editor, contentRow(OTHER))

      const res = await req('PUT', { title: 'Hello (updated)' })
      expect(res.status).toBe(200)
    })

    it('returns 403 at the coarse gate when the user lacks content:update entirely', async () => {
      mockCan.mockResolvedValue(false) // requireRbac denies before the handler
      const { req } = buildApp(editor, contentRow(OWNER))

      const res = await req('PUT', { title: 'x' })
      expect(res.status).toBe(403)
      // The fine-grained scope lookup is never reached.
      expect(mockGetPermissionScope).not.toHaveBeenCalled()
    })

    it('returns 404 when the record does not exist', async () => {
      mockGetPermissionScope.mockResolvedValue('any')
      const { req } = buildApp(editor, null)

      const res = await req('PUT', { title: 'x' })
      expect(res.status).toBe(404)
    })
  })

  describe('DELETE /api/content/:id', () => {
    it('allows an own-scoped author to delete their own record', async () => {
      mockGetPermissionScope.mockResolvedValue('own')
      const { req } = buildApp(editor, contentRow(OWNER))

      const res = await req('DELETE')
      expect(res.status).toBe(200)
      expect(await res.json()).toEqual({ success: true })
    })

    it("blocks an own-scoped author from deleting another author's record", async () => {
      mockGetPermissionScope.mockResolvedValue('own')
      const { req } = buildApp(editor, contentRow(OTHER))

      const res = await req('DELETE')
      expect(res.status).toBe(403)
      expect(await res.json()).toEqual({ error: 'Insufficient permissions' })
    })

    it('allows an any-scoped user to delete any record', async () => {
      mockGetPermissionScope.mockResolvedValue('any')
      const { req } = buildApp(editor, contentRow(OTHER))

      const res = await req('DELETE')
      expect(res.status).toBe(200)
    })
  })
})
