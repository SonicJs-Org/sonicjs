import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Hono } from 'hono'

// Helper to create mock user with specific role
const createMockUser = (role: string = 'admin') => ({
  userId: 'admin-1',
  email: 'admin@test.com',
  role
})

// Mock the requireAuth middleware to bypass authentication in tests
vi.mock('../../middleware', () => ({
  requireAuth: () => {
    return async (c: any, next: any) => {
      c.set('user', createMockUser())
      await next()
    }
  },
  requireRole: () => {
    return async (_c: any, next: any) => {
      await next()
    }
  },
  logActivity: vi.fn(),
  AuthManager: {
    generateToken: vi.fn(),
    verifyToken: vi.fn(),
    hashPassword: vi.fn()
  }
}))

// Mock sanitizeInput to pass through (tested elsewhere)
vi.mock('../../utils/sanitize', () => ({
  sanitizeInput: (val: any) => val
}))

// Mock template modules — return JSON-stringified data for inspection
vi.mock('../../templates/pages/admin-user-edit.template', () => ({
  renderUserEditPage: (data: any) => JSON.stringify(data),
  UserEditPageData: {},
  UserEditData: {},
  UserProfileData: {}
}))

vi.mock('../../templates/pages/admin-profile.template', () => ({
  renderProfilePage: (data: any) => JSON.stringify(data),
  renderAvatarImage: () => '<img />',
  UserProfile: {},
  ProfilePageData: {}
}))

vi.mock('../../templates/components/alert.template', () => ({
  renderAlert: (data: any) => JSON.stringify(data)
}))

vi.mock('../../templates/pages/admin-activity-logs.template', () => ({
  renderActivityLogsPage: (data: any) => JSON.stringify(data),
  ActivityLogsPageData: {},
  ActivityLog: {}
}))

vi.mock('../../templates/pages/admin-user-new.template', () => ({
  renderUserNewPage: (data: any) => JSON.stringify(data),
  UserNewPageData: {}
}))

vi.mock('../../templates/pages/admin-users-list.template', () => ({
  renderUsersListPage: (data: any) => JSON.stringify(data),
  UsersListPageData: {},
  User: {}
}))

import { userRoutes } from '../../routes/admin-users'

// Create call-order based D1 mock
// Each db.prepare() call returns a distinct mock chain based on call index
const createOrderedMockDb = (results: Array<{ first?: any; run?: any; all?: any }>) => {
  let callIndex = 0
  return {
    prepare: vi.fn().mockImplementation(() => {
      const result = results[callIndex++] || {}
      return {
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue(result.first ?? null),
          run: vi.fn().mockResolvedValue(result.run ?? { success: true }),
          all: vi.fn().mockResolvedValue(result.all ?? { results: [] })
        })
      }
    })
  }
}

// Standard mock user record
const mockUserRecord = {
  id: 'user-123',
  email: 'test@example.com',
  username: 'testuser',
  first_name: 'Test',
  last_name: 'User',
  phone: null,
  avatar_url: null,
  role: 'viewer',
  is_active: 1,
  email_verified: 0,
  two_factor_enabled: 0,
  created_at: Date.now(),
  last_login_at: null
}

// Standard mock profile record
const mockProfileRecord = {
  display_name: 'Test Display',
  bio: 'A test bio',
  company: 'Test Corp',
  job_title: 'Engineer',
  website: 'https://example.com',
  location: 'San Francisco',
  date_of_birth: 631152000000
}

describe('Admin Users - Profile on Edit Page', () => {
  let app: Hono
  let mockDb: any

  beforeEach(() => {
    vi.clearAllMocks()
  })

  const createApp = (db: any) => {
    app = new Hono()
    app.route('/admin', userRoutes)
    return app
  }

  describe('GET /admin/users/:id/edit', () => {
    it('should render edit page with profile data when profile exists', async () => {
      mockDb = createOrderedMockDb([
        { first: mockUserRecord },    // call 0: SELECT FROM users
        { first: mockProfileRecord }  // call 1: SELECT FROM user_profiles
      ])

      app = createApp(mockDb)

      const res = await app.request('/admin/users/user-123/edit', {}, {
        DB: mockDb,
        KV: {},
        CACHE_KV: {}
      })

      expect(res.status).toBe(200)

      const body = await res.text()
      const data = JSON.parse(body)

      // Verify profile data is mapped to camelCase interface
      expect(data.userToEdit.profile).toBeDefined()
      expect(data.userToEdit.profile.displayName).toBe('Test Display')
      expect(data.userToEdit.profile.bio).toBe('A test bio')
      expect(data.userToEdit.profile.company).toBe('Test Corp')
      expect(data.userToEdit.profile.jobTitle).toBe('Engineer')
      expect(data.userToEdit.profile.website).toBe('https://example.com')
      expect(data.userToEdit.profile.location).toBe('San Francisco')

      // Verify db.prepare was called twice (user + profile)
      expect(mockDb.prepare).toHaveBeenCalledTimes(2)
    })

    it('should render edit page with undefined profile when no profile exists', async () => {
      mockDb = createOrderedMockDb([
        { first: mockUserRecord },  // call 0: SELECT FROM users
        { first: null }             // call 1: SELECT FROM user_profiles — no profile
      ])

      app = createApp(mockDb)

      const res = await app.request('/admin/users/user-123/edit', {}, {
        DB: mockDb,
        KV: {},
        CACHE_KV: {}
      })

      expect(res.status).toBe(200)

      const body = await res.text()
      const data = JSON.parse(body)

      // Profile should be undefined, page should still render
      expect(data.userToEdit.profile).toBeUndefined()
      expect(data.userToEdit.id).toBe('user-123')
    })

    it('should return 404 when user not found', async () => {
      mockDb = createOrderedMockDb([
        { first: null }  // call 0: SELECT FROM users — not found
      ])

      app = createApp(mockDb)

      const res = await app.request('/admin/users/nonexistent/edit', {}, {
        DB: mockDb,
        KV: {},
        CACHE_KV: {}
      })

      expect(res.status).toBe(404)

      const body = await res.text()
      const data = JSON.parse(body)
      expect(data.type).toBe('error')
      expect(data.message).toContain('not found')
    })

    it('should return 500 on database error', async () => {
      mockDb = {
        prepare: vi.fn().mockImplementation(() => {
          throw new Error('D1 database error')
        })
      }

      app = createApp(mockDb)

      const res = await app.request('/admin/users/user-123/edit', {}, {
        DB: mockDb,
        KV: {},
        CACHE_KV: {}
      })

      expect(res.status).toBe(500)

      const body = await res.text()
      const data = JSON.parse(body)
      expect(data.type).toBe('error')
      expect(data.message).toContain('Failed to load user')
    })
  })

  describe('PUT /admin/users/:id', () => {
    const createFormBody = (fields: Record<string, string>) => {
      const params = new URLSearchParams()
      for (const [key, value] of Object.entries(fields)) {
        params.append(key, value)
      }
      return params.toString()
    }

    const baseUserFields = {
      first_name: 'Test',
      last_name: 'User',
      username: 'testuser',
      email: 'test@example.com',
      role: 'viewer',
      is_active: '1'
    }

    it('should update existing profile when profile record exists', async () => {
      mockDb = createOrderedMockDb([
        { first: null },                                // call 0: SELECT id FROM users WHERE (username=? OR email=?) — uniqueness check, no conflict
        { run: { success: true } },                     // call 1: UPDATE users SET ...
        { first: { id: 'profile-existing' } },          // call 2: SELECT id FROM user_profiles WHERE user_id=?
        { run: { success: true } }                      // call 3: UPDATE user_profiles SET ...
      ])

      app = createApp(mockDb)

      const body = createFormBody({
        ...baseUserFields,
        profile_display_name: 'Updated Name',
        profile_company: 'New Corp'
      })

      const res = await app.request('/admin/users/user-123', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body
      }, {
        DB: mockDb,
        KV: {},
        CACHE_KV: {}
      })

      expect(res.status).toBe(200)

      const responseBody = await res.text()
      const data = JSON.parse(responseBody)
      expect(data.type).toBe('success')

      // Verify all 4 prepare calls were made (uniqueness + update + profile check + profile update)
      expect(mockDb.prepare.mock.calls.length).toBeGreaterThanOrEqual(4)
    })

    it('should create new profile when no profile record exists', async () => {
      mockDb = createOrderedMockDb([
        { first: null },                // call 0: SELECT id FROM users — uniqueness check, no conflict
        { run: { success: true } },     // call 1: UPDATE users SET ...
        { first: null },                // call 2: SELECT id FROM user_profiles — not found
        { run: { success: true } }      // call 3: INSERT INTO user_profiles
      ])

      app = createApp(mockDb)

      const body = createFormBody({
        ...baseUserFields,
        profile_display_name: 'New Profile',
        profile_bio: 'A new bio'
      })

      const res = await app.request('/admin/users/user-123', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body
      }, {
        DB: mockDb,
        KV: {},
        CACHE_KV: {}
      })

      expect(res.status).toBe(200)

      const responseBody = await res.text()
      const data = JSON.parse(responseBody)
      expect(data.type).toBe('success')

      // Verify all 4 prepare calls were made (uniqueness + update + profile check + profile insert)
      expect(mockDb.prepare.mock.calls.length).toBeGreaterThanOrEqual(4)
    })

    it('should skip profile queries when no profile fields are submitted', async () => {
      mockDb = createOrderedMockDb([
        { first: null },                // call 0: SELECT id FROM users — uniqueness check, no conflict
        { run: { success: true } }      // call 1: UPDATE users SET ...
      ])

      app = createApp(mockDb)

      // Submit only user fields — no profile_* keys at all
      const body = createFormBody(baseUserFields)

      const res = await app.request('/admin/users/user-123', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body
      }, {
        DB: mockDb,
        KV: {},
        CACHE_KV: {}
      })

      expect(res.status).toBe(200)

      const responseBody = await res.text()
      const data = JSON.parse(responseBody)
      expect(data.type).toBe('success')

      // With no profile fields, hasProfileData is falsy (all null via || null).
      // The profile block (SELECT/INSERT/UPDATE on user_profiles) should be skipped entirely.
      // Only 2 prepare calls: uniqueness check + user update.
      // logActivity is mocked so it won't add more.
      expect(mockDb.prepare.mock.calls.length).toBe(2)
    })

    it('should return error on profile database failure', async () => {
      mockDb = createOrderedMockDb([
        { first: null },                // call 0: SELECT id FROM users — uniqueness check, no conflict
        { run: { success: true } },     // call 1: UPDATE users SET ...
        {}                              // call 2: SELECT id FROM user_profiles — will be overridden below
      ])

      // Override call 2 to throw an error on .first()
      let callCount = 0
      mockDb.prepare = vi.fn().mockImplementation(() => {
        callCount++
        if (callCount === 3) {
          // 3rd prepare call: profile existence check — throw error
          return {
            bind: vi.fn().mockReturnValue({
              first: vi.fn().mockRejectedValue(new Error('D1 profile table error')),
              run: vi.fn().mockRejectedValue(new Error('D1 profile table error')),
              all: vi.fn().mockResolvedValue({ results: [] })
            })
          }
        }
        // Calls 1-2: uniqueness check (return null) and user update (success)
        return {
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue(null),
            run: vi.fn().mockResolvedValue({ success: true }),
            all: vi.fn().mockResolvedValue({ results: [] })
          })
        }
      })

      app = createApp(mockDb)

      const body = createFormBody({
        ...baseUserFields,
        profile_display_name: 'Will Fail'
      })

      const res = await app.request('/admin/users/user-123', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body
      }, {
        DB: mockDb,
        KV: {},
        CACHE_KV: {}
      })

      const responseBody = await res.text()
      const data = JSON.parse(responseBody)
      expect(data.type).toBe('error')
      expect(data.message).toContain('Failed to update user')
    })
  })
})
