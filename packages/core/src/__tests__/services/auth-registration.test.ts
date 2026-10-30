import { describe, it, expect, vi, beforeEach } from 'vitest'
import { isRegistrationEnabled, isFirstUserRegistration } from '../../services/auth-validation'

// Mock D1Database
const createMockDb = () => ({
  prepare: vi.fn().mockReturnThis(),
  bind: vi.fn().mockReturnThis(),
  first: vi.fn(),
  all: vi.fn(),
  run: vi.fn()
})

describe('Registration Settings', () => {
  describe('isRegistrationEnabled', () => {
    let mockDb: ReturnType<typeof createMockDb>

    beforeEach(() => {
      mockDb = createMockDb()
    })

    it('should return true when registration is explicitly enabled', async () => {
      mockDb.first.mockResolvedValue({
        settings: JSON.stringify({
          registration: {
            enabled: true,
            requireEmailVerification: false,
            defaultRole: 'viewer'
          }
        })
      })

      const result = await isRegistrationEnabled(mockDb as any)

      expect(result).toBe(true)
      expect(mockDb.prepare).toHaveBeenCalledWith('SELECT settings FROM plugins WHERE id = ?')
      expect(mockDb.bind).toHaveBeenCalledWith('core-auth')
    })

    it('should return false when registration is explicitly disabled (boolean false)', async () => {
      mockDb.first.mockResolvedValue({
        settings: JSON.stringify({
          registration: {
            enabled: false,
            requireEmailVerification: false,
            defaultRole: 'viewer'
          }
        })
      })

      const result = await isRegistrationEnabled(mockDb as any)

      expect(result).toBe(false)
    })

    it('should return false when registration is disabled with 0 (SQLite boolean)', async () => {
      // SQLite stores booleans as 0/1, so we need to handle this case
      mockDb.first.mockResolvedValue({
        settings: JSON.stringify({
          registration: {
            enabled: 0,
            requireEmailVerification: 0,
            defaultRole: 'viewer'
          }
        })
      })

      const result = await isRegistrationEnabled(mockDb as any)

      expect(result).toBe(false)
    })

    it('should return true when registration is enabled with 1 (SQLite boolean)', async () => {
      mockDb.first.mockResolvedValue({
        settings: JSON.stringify({
          registration: {
            enabled: 1,
            requireEmailVerification: 0,
            defaultRole: 'viewer'
          }
        })
      })

      const result = await isRegistrationEnabled(mockDb as any)

      expect(result).toBe(true)
    })

    it('should return true when no settings exist (default behavior)', async () => {
      mockDb.first.mockResolvedValue(null)

      const result = await isRegistrationEnabled(mockDb as any)

      expect(result).toBe(true)
    })

    it('should return true when settings exist but registration key is missing', async () => {
      mockDb.first.mockResolvedValue({
        settings: JSON.stringify({
          someOtherSetting: true
        })
      })

      const result = await isRegistrationEnabled(mockDb as any)

      expect(result).toBe(true)
    })

    it('should return true when registration object exists but enabled key is missing', async () => {
      mockDb.first.mockResolvedValue({
        settings: JSON.stringify({
          registration: {
            requireEmailVerification: false,
            defaultRole: 'viewer'
          }
        })
      })

      const result = await isRegistrationEnabled(mockDb as any)

      expect(result).toBe(true)
    })

    it('should return true on database error (fail-safe)', async () => {
      mockDb.first.mockRejectedValue(new Error('Database connection failed'))

      const result = await isRegistrationEnabled(mockDb as any)

      expect(result).toBe(true)
    })

    it('should return true on JSON parse error (fail-safe)', async () => {
      mockDb.first.mockResolvedValue({
        settings: 'invalid json {'
      })

      const result = await isRegistrationEnabled(mockDb as any)

      expect(result).toBe(true)
    })

    it('should handle empty settings string', async () => {
      mockDb.first.mockResolvedValue({
        settings: ''
      })

      const result = await isRegistrationEnabled(mockDb as any)

      // Empty string will throw JSON parse error, which returns true (fail-safe)
      expect(result).toBe(true)
    })
  })

  describe('isFirstUserRegistration', () => {
    let mockDb: ReturnType<typeof createMockDb>

    beforeEach(() => {
      mockDb = createMockDb()
    })

    it('should return true when no users exist', async () => {
      mockDb.first.mockResolvedValue({ count: 0 })

      const result = await isFirstUserRegistration(mockDb as any)

      expect(result).toBe(true)
      expect(mockDb.prepare).toHaveBeenCalledWith('SELECT COUNT(*) as count FROM auth_user')
    })

    it('should return false when users exist', async () => {
      mockDb.first.mockResolvedValue({ count: 1 })

      const result = await isFirstUserRegistration(mockDb as any)

      expect(result).toBe(false)
    })

    it('should return false when multiple users exist', async () => {
      mockDb.first.mockResolvedValue({ count: 10 })

      const result = await isFirstUserRegistration(mockDb as any)

      expect(result).toBe(false)
    })

    it('should return false on database error (fail-safe)', async () => {
      mockDb.first.mockRejectedValue(new Error('Database connection failed'))

      const result = await isFirstUserRegistration(mockDb as any)

      expect(result).toBe(false)
    })

    it('should return false when query returns null', async () => {
      mockDb.first.mockResolvedValue(null)

      const result = await isFirstUserRegistration(mockDb as any)

      expect(result).toBe(false)
    })
  })

  describe('Registration flow logic', () => {
    let mockDb: ReturnType<typeof createMockDb>

    beforeEach(() => {
      mockDb = createMockDb()
    })

    it('should allow first user registration even when registration is disabled', async () => {
      // This tests the combined logic that should be used in the route handlers
      mockDb.first
        .mockResolvedValueOnce({ count: 0 }) // First call - isFirstUserRegistration
        .mockResolvedValueOnce({              // Second call - isRegistrationEnabled
          settings: JSON.stringify({
            registration: { enabled: false }
          })
        })

      const isFirstUser = await isFirstUserRegistration(mockDb as any)

      // First user should always be allowed, so we don't need to check registration setting
      if (!isFirstUser) {
        const isEnabled = await isRegistrationEnabled(mockDb as any)
        expect(isEnabled).toBe(false)
      }

      expect(isFirstUser).toBe(true)
    })

    it('should block non-first user registration when disabled', async () => {
      // Reset mock for fresh call tracking
      mockDb = createMockDb()

      mockDb.first
        .mockResolvedValueOnce({ count: 1 }) // First call - isFirstUserRegistration (user exists)
        .mockResolvedValueOnce({              // Second call - isRegistrationEnabled (plugin document)
          data: JSON.stringify({
            settings: { registration: { enabled: false } }
          })
        })

      const isFirstUser = await isFirstUserRegistration(mockDb as any)
      expect(isFirstUser).toBe(false)

      const isEnabled = await isRegistrationEnabled(mockDb as any)
      expect(isEnabled).toBe(false)

      // Combined: should block registration
      const shouldAllowRegistration = isFirstUser || isEnabled
      expect(shouldAllowRegistration).toBe(false)
    })

    it('should allow non-first user registration when enabled', async () => {
      // Reset mock for fresh call tracking
      mockDb = createMockDb()

      mockDb.first
        .mockResolvedValueOnce({ count: 1 }) // First call - isFirstUserRegistration (user exists)
        .mockResolvedValueOnce({              // Second call - isRegistrationEnabled (plugin document)
          data: JSON.stringify({
            settings: { registration: { enabled: true } }
          })
        })

      const isFirstUser = await isFirstUserRegistration(mockDb as any)
      expect(isFirstUser).toBe(false)

      const isEnabled = await isRegistrationEnabled(mockDb as any)
      expect(isEnabled).toBe(true)

      // Combined: should allow registration
      const shouldAllowRegistration = isFirstUser || isEnabled
      expect(shouldAllowRegistration).toBe(true)
    })
  })
})
