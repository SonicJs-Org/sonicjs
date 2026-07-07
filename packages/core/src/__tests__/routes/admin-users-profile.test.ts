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

vi.mock('../../plugins/core-plugins/user-profiles', () => ({
  getUserProfileConfig: vi.fn().mockReturnValue(undefined),
  renderCustomProfileSection: vi.fn().mockReturnValue(''),
  getCustomData: vi.fn().mockResolvedValue({}),
  saveCustomData: vi.fn(),
  extractCustomFieldsFromForm: vi.fn().mockReturnValue({}),
  sanitizeCustomData: vi.fn().mockReturnValue({}),
  validateCustomData: vi.fn().mockReturnValue({ valid: true, errors: {} }),
  // Profile storage is document-backed; the route reads/writes via these.
  readProfileData: vi.fn().mockResolvedValue({ custom: {} }),
  writeProfileData: vi.fn().mockResolvedValue(undefined),
}))

import { userRoutes } from '../../routes/admin-users'

// Create call-order based D1 mock
// Each db.prepare() call returns a distinct mock chain based on call index.
// The prepared statement supports both the `.bind(...).first()/.run()/.all()`
// chain and the un-bound `.first()/.run()/.all()` shorthand (the edit handler's
// multi-tenant probe calls `.first()` directly without `.bind()`).
const createOrderedMockDb = (results: Array<{ first?: any; run?: any; all?: any }>) => {
  let callIndex = 0
  return {
    prepare: vi.fn().mockImplementation(() => {
      const result = results[callIndex++] || {}
      const terminals = {
        first: vi.fn().mockResolvedValue(result.first ?? null),
        run: vi.fn().mockResolvedValue(result.run ?? { success: true }),
        all: vi.fn().mockResolvedValue(result.all ?? { results: [] })
      }
      return {
        bind: vi.fn().mockReturnValue(terminals),
        ...terminals
      }
    })
  }
}

// Standard mock user record
const mockUserRecord = {
  id: 'user-123',
  email: 'test@example.com',
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

// Standard mock profile document data (shape returned by readProfileData)
const mockProfileData = {
  displayName: 'Test Display',
  bio: 'A test bio',
  company: 'Test Corp',
  jobTitle: 'Engineer',
  website: 'https://example.com',
  location: 'San Francisco',
  dateOfBirth: 631152000000,
  custom: {} as Record<string, any>,
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
      const { readProfileData } = await import('../../plugins/core-plugins/user-profiles')
      vi.mocked(readProfileData).mockResolvedValue({ ...mockProfileData })

      mockDb = createOrderedMockDb([
        { first: mockUserRecord },    // call 0: SELECT FROM auth_user (profile comes from readProfileData)
        { first: null },              // call 1: multi-tenant plugin probe — inactive
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

      // The edit page maps only displayName onto the UserProfileData interface;
      // the rest of the document data is not surfaced on this page.
      expect(data.userToEdit.profile).toBeDefined()
      expect(data.userToEdit.profile.displayName).toBe('Test Display')

      // Profile read is delegated to the document store, not a raw SQL query.
      expect(readProfileData).toHaveBeenCalledWith(mockDb, 'user-123')
    })

    it('should render edit page with undefined profile when no profile exists', async () => {
      const { readProfileData } = await import('../../plugins/core-plugins/user-profiles')
      vi.mocked(readProfileData).mockResolvedValue({ custom: {} })

      mockDb = createOrderedMockDb([
        { first: mockUserRecord },  // call 0: SELECT FROM auth_user
        { first: null },            // call 1: multi-tenant plugin probe — inactive
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
      email: 'test@example.com',
      role: 'viewer',
      is_active: '1'
    }

    it('should write the profile document when profile fields are submitted', async () => {
      const { writeProfileData } = await import('../../plugins/core-plugins/user-profiles')
      mockDb = createOrderedMockDb([
        { first: null },                                // call 0: uniqueness check, no conflict
        { run: { success: true } },                     // call 1: UPDATE users SET ...
      ])

      app = createApp(mockDb)

      const body = createFormBody({
        ...baseUserFields,
        profile_display_name: 'Updated Name'
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

      // Profile persisted via the document store. The edit form only feeds the
      // typed `displayName` field into the patch (other profile columns were
      // dropped from the UserProfileData interface).
      expect(writeProfileData).toHaveBeenCalledTimes(1)
      const [, userIdArg, patch] = vi.mocked(writeProfileData).mock.calls[0] as any[]
      expect(userIdArg).toBe('user-123')
      expect(patch.displayName).toBe('Updated Name')
    })

    it('should skip the profile write when no profile fields are submitted', async () => {
      const { writeProfileData } = await import('../../plugins/core-plugins/user-profiles')
      mockDb = createOrderedMockDb([
        { all: { results: [] } },       // call 0: RbacService.getRoles() — no custom roles
        { first: null },                // call 1: uniqueness check, no conflict
        { run: { success: true } }      // call 2: UPDATE users SET ...
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

      // No profile fields + no custom config → profile write skipped entirely.
      expect(writeProfileData).not.toHaveBeenCalled()
      // Only 3 prepare calls: getRoles (role validation) + uniqueness check + user update.
      expect(mockDb.prepare.mock.calls.length).toBe(3)
    })

    it('should write custom profile data even when no standard profile fields are set (issue #768)', async () => {
      // Mock getUserProfileConfig to return a config with custom fields
      const { getUserProfileConfig, extractCustomFieldsFromForm, sanitizeCustomData, writeProfileData } = await import('../../plugins/core-plugins/user-profiles')
      vi.mocked(getUserProfileConfig).mockReturnValue({
        fields: [
          { name: 'plan', label: 'Plan', type: 'radio', options: ['free', 'monthly', 'annual', 'lifetime'], default: 'free', required: true }
        ]
      } as any)
      vi.mocked(extractCustomFieldsFromForm).mockReturnValue({ plan: 'monthly' })
      vi.mocked(sanitizeCustomData).mockReturnValue({ plan: 'monthly' })

      mockDb = createOrderedMockDb([
        { first: null },                // call 0: uniqueness check — no conflict
        { run: { success: true } },     // call 1: UPDATE users SET ...
      ])

      app = createApp(mockDb)

      // Submit only user fields + custom field — no standard profile_* keys
      const body = createFormBody({
        ...baseUserFields,
        'custom_plan': 'monthly'
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
      const data = JSON.parse(await res.text())
      expect(data.type).toBe('success')

      // Profile write is NOT skipped when only custom data is present; the custom
      // namespace is passed through to the document store.
      expect(writeProfileData).toHaveBeenCalledTimes(1)
      const [, , patch] = vi.mocked(writeProfileData).mock.calls[0] as any[]
      expect(patch.custom).toEqual({ plan: 'monthly' })

      // Reset mocks
      vi.mocked(getUserProfileConfig).mockReturnValue(undefined as any)
    })

    it('should return error on profile write failure', async () => {
      const { writeProfileData } = await import('../../plugins/core-plugins/user-profiles')
      vi.mocked(writeProfileData).mockRejectedValueOnce(new Error('document write failed'))

      mockDb = createOrderedMockDb([
        { first: null },                // call 0: uniqueness check, no conflict
        { run: { success: true } },     // call 1: UPDATE users SET ...
      ])

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
