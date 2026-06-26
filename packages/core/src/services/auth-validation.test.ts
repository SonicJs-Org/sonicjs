/**
 * Auth Validation Service Tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  checkAdminUserExists,
  setAdminExists,
  resetAdminExistsCache,
  isFirstUserRegistration,
  isRegistrationEnabled
} from './auth-validation'

// Mock D1Database
function createMockDb(options: {
  adminExists?: boolean
  userCount?: number
  registrationEnabled?: boolean
  shouldThrow?: boolean
} = {}) {
  const { adminExists = false, userCount = 0, registrationEnabled = true, shouldThrow = false } = options

  return {
    prepare: vi.fn((sql: string) => {
      // For queries that need bind()
      if (sql.includes('role = ?') || sql.includes('plugins WHERE id')) {
        return {
          bind: vi.fn(() => ({
            first: vi.fn(async () => {
              if (shouldThrow) {
                throw new Error('Database error')
              }

              // Check for admin user query
              if (sql.includes('role = ?')) {
                return adminExists ? { id: 'admin-id' } : null
              }

              // Check for plugin settings query
              if (sql.includes('plugins WHERE id')) {
                return registrationEnabled
                  ? { settings: JSON.stringify({ registration: { enabled: true } }) }
                  : { settings: JSON.stringify({ registration: { enabled: false } }) }
              }

              return null
            })
          }))
        }
      }

      // For queries that don't need bind() (like COUNT(*))
      return {
        bind: vi.fn(() => ({
          first: vi.fn(async () => {
            if (shouldThrow) {
              throw new Error('Database error')
            }
            return null
          })
        })),
        first: vi.fn(async () => {
          if (shouldThrow) {
            throw new Error('Database error')
          }

          // Check for user count query
          if (sql.includes('COUNT(*)')) {
            return { count: userCount }
          }

          return null
        })
      }
    })
  } as any
}

describe('Auth Validation Service', () => {
  beforeEach(() => {
    // Reset the cache before each test
    resetAdminExistsCache()
  })

  describe('checkAdminUserExists', () => {
    it('should return false when no admin user exists', async () => {
      const db = createMockDb({ adminExists: false })
      const result = await checkAdminUserExists(db)
      expect(result).toBe(false)
    })

    it('should return true when admin user exists', async () => {
      const db = createMockDb({ adminExists: true })
      const result = await checkAdminUserExists(db)
      expect(result).toBe(true)
    })

    it('should cache the result and not query again', async () => {
      const db = createMockDb({ adminExists: true })

      // First call - should query DB
      const result1 = await checkAdminUserExists(db)
      expect(result1).toBe(true)
      expect(db.prepare).toHaveBeenCalledTimes(1)

      // Second call - should use cache
      const result2 = await checkAdminUserExists(db)
      expect(result2).toBe(true)
      expect(db.prepare).toHaveBeenCalledTimes(1) // Still 1, not 2
    })

    it('should return false on database error', async () => {
      const db = createMockDb({ shouldThrow: true })
      const result = await checkAdminUserExists(db)
      expect(result).toBe(false)
    })
  })

  describe('setAdminExists', () => {
    it('should set the cache to true', async () => {
      const db = createMockDb({ adminExists: false })

      // First check - no admin
      const result1 = await checkAdminUserExists(db)
      expect(result1).toBe(false)

      // Reset cache to test setAdminExists
      resetAdminExistsCache()

      // Set admin exists
      setAdminExists()

      // Now check should return true without querying DB
      const result2 = await checkAdminUserExists(db)
      expect(result2).toBe(true)
      // DB should not have been queried again (only 1 call from first check)
      expect(db.prepare).toHaveBeenCalledTimes(1)
    })
  })

  describe('resetAdminExistsCache', () => {
    it('should reset the cache so next call queries DB', async () => {
      const db = createMockDb({ adminExists: true })

      // First call - queries DB
      await checkAdminUserExists(db)
      expect(db.prepare).toHaveBeenCalledTimes(1)

      // Reset cache
      resetAdminExistsCache()

      // Next call should query DB again
      await checkAdminUserExists(db)
      expect(db.prepare).toHaveBeenCalledTimes(2)
    })
  })

  describe('isFirstUserRegistration', () => {
    it('should return true when no users exist', async () => {
      const db = createMockDb({ userCount: 0 })
      const result = await isFirstUserRegistration(db)
      expect(result).toBe(true)
    })

    it('should return false when users exist', async () => {
      const db = createMockDb({ userCount: 5 })
      const result = await isFirstUserRegistration(db)
      expect(result).toBe(false)
    })

    it('should return false on database error', async () => {
      const db = createMockDb({ shouldThrow: true })
      const result = await isFirstUserRegistration(db)
      expect(result).toBe(false)
    })
  })

  describe('isRegistrationEnabled', () => {
    it('should return true when registration is enabled', async () => {
      const db = createMockDb({ registrationEnabled: true })
      const result = await isRegistrationEnabled(db)
      expect(result).toBe(true)
    })

    it('should return false when registration is disabled', async () => {
      const db = createMockDb({ registrationEnabled: false })
      const result = await isRegistrationEnabled(db)
      expect(result).toBe(false)
    })

    it('should return true on database error (default)', async () => {
      const db = createMockDb({ shouldThrow: true })
      const result = await isRegistrationEnabled(db)
      expect(result).toBe(true)
    })

    it('should return true when no plugin settings exist', async () => {
      const db = {
        prepare: vi.fn(() => ({
          bind: vi.fn(() => ({
            first: vi.fn(async () => null) // No plugin found
          }))
        }))
      } as any

      const result = await isRegistrationEnabled(db)
      expect(result).toBe(true)
    })

    it('should return false when registration.enabled is 0 (SQLite boolean)', async () => {
      const db = {
        prepare: vi.fn(() => ({
          bind: vi.fn(() => ({
            first: vi.fn(async () => ({
              settings: JSON.stringify({ registration: { enabled: 0 } })
            }))
          }))
        }))
      } as any

      const result = await isRegistrationEnabled(db)
      expect(result).toBe(false)
    })
  })
})

describe('authValidationService', () => {
  describe('buildRegistrationSchema', () => {
    it('should return a registration schema', async () => {
      const { authValidationService } = await import('./auth-validation')
      const db = createMockDb()

      const schema = await authValidationService.buildRegistrationSchema(db)

      expect(schema).toBeDefined()
      // The schema should be a zod schema that we can use to parse data
      const validData = {
        email: 'test@example.com',
        password: 'password123'
      }
      const result = schema.safeParse(validData)
      expect(result.success).toBe(true)
    })

    it('should reject invalid email', async () => {
      const { authValidationService } = await import('./auth-validation')
      const db = createMockDb()

      const schema = await authValidationService.buildRegistrationSchema(db)

      const invalidData = {
        email: 'not-an-email',
        password: 'password123'
      }
      const result = schema.safeParse(invalidData)
      expect(result.success).toBe(false)
    })

    it('should reject short password', async () => {
      const { authValidationService } = await import('./auth-validation')
      const db = createMockDb()

      const schema = await authValidationService.buildRegistrationSchema(db)

      const invalidData = {
        email: 'test@example.com',
        password: 'short'
      }
      const result = schema.safeParse(invalidData)
      expect(result.success).toBe(false)
    })

    // Email-format edge cases — mirrors Payload's `Email - format validation`
    // suite. Confirms our registration schema rejects malformed addresses.
    describe('email format edge cases', () => {
      const accept = ['test@example.com', 'john.doe+tag@sub.example.co.uk', 'a_b@example.io']
      const reject = [
        'plainaddress',
        'two"quotes"@example.com',
        'has space@example.com',
        'consecutive..dots@example.com',
        '.leadingdot@example.com',
        'comma,addr@example.com',
        'no-at-sign.example.com',
        'user@-example.com', // domain label starts with hyphen
        'user@example-.com', // domain label ends with hyphen
        'user@example..com', // empty domain label
      ]

      it.each(accept)('accepts %s', async (email) => {
        const { authValidationService } = await import('./auth-validation')
        const schema = await authValidationService.buildRegistrationSchema(createMockDb())
        expect(schema.safeParse({ email, password: 'password123' }).success).toBe(true)
      })

      it.each(reject)('rejects %s', async (email) => {
        const { authValidationService } = await import('./auth-validation')
        const schema = await authValidationService.buildRegistrationSchema(createMockDb())
        expect(schema.safeParse({ email, password: 'password123' }).success).toBe(false)
      })
    })

  })

  describe('generateDefaultValue', () => {
    it('should generate default firstName', async () => {
      const { authValidationService } = await import('./auth-validation')

      const result = authValidationService.generateDefaultValue('firstName', {})

      expect(result).toBe('User')
    })

    it('should generate lastName from email', async () => {
      const { authValidationService } = await import('./auth-validation')

      const result = authValidationService.generateDefaultValue('lastName', {
        email: 'john.doe@example.com'
      })

      expect(result).toBe('john.doe')
    })

    it('should generate fallback lastName when no email', async () => {
      const { authValidationService } = await import('./auth-validation')

      const result = authValidationService.generateDefaultValue('lastName', {})

      expect(result).toBe('Account')
    })

    it('should return empty string for unknown field', async () => {
      const { authValidationService } = await import('./auth-validation')

      const result = authValidationService.generateDefaultValue('unknownField', {
        email: 'test@example.com'
      })

      expect(result).toBe('')
    })
  })
})
