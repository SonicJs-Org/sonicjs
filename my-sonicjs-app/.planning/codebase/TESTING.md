# Testing Patterns

**Analysis Date:** 2026-01-30

## Test Framework

**Runner:** Vitest v2.1.8
- Config: `vitest.config.ts` at repository root
- Environment: Node.js
- Globals enabled: `true` (describe, it, expect available without imports)

**Assertion Library:** Vitest native (expect)
- Follows Vitest/Jest API
- No separate assertion library needed

**Run Commands:**
```bash
npm run test                # Run all tests once
npm run test:watch         # Watch mode (re-run on changes)
npm run test:cov           # Run with coverage report
```

**Coverage Provider:** v8

## Test File Organization

### Location Patterns

**Tests co-located with source code:**

Pattern 1 - File suffix:
```
src/
  services/
    user-service.ts
    user-service.test.ts    # Adjacent to source
  middleware/
    auth.ts
    auth.test.ts
```

Pattern 2 - Dedicated test directory:
```
src/
  services/
    user-service.ts
    __tests__/
      user-service.test.ts
      user-service.integration.test.ts
  __tests__/
    middleware/
      auth.test.ts
    utils/
      sanitize.test.ts
```

Actual locations in codebase:
- `packages/core/src/services/auth-validation.test.ts` (suffix pattern)
- `packages/core/src/__tests__/middleware/auth.test.ts` (dedicated directory)
- `packages/core/src/plugins/cache/tests/cache.test.ts` (plugin subdirectory)
- `packages/core/src/plugins/core-plugins/turnstile-plugin/__tests__/turnstile.test.ts`

### File Naming

**Pattern:** `[module-name].test.ts` or `[module-name].spec.ts`

Examples:
- `auth.test.ts` - Test the auth module
- `cache.test.ts` - Test cache service
- `sanitize.test.ts` - Test sanitize utilities
- `settings.test.ts` - Test settings service

## Test Structure

### Describe and It Organization

**Top-level describe per class/module:**
```typescript
describe('AuthManager', () => {
  describe('generateToken', () => {
    it('should generate a valid JWT token', async () => {
      // ...
    })

    it('should generate unique tokens for different users', async () => {
      // ...
    })
  })

  describe('verifyToken', () => {
    it('should verify a valid token', async () => {
      // ...
    })

    it('should return null for invalid token', async () => {
      // ...
    })
  })
})
```

**Nested describe blocks for method groups:**
Each method/function gets its own describe block containing related tests.

### Setup and Teardown

**beforeEach for common setup:**
```typescript
describe('SettingsService', () => {
  let settingsService: SettingsService
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    settingsService = new SettingsService(mockDb as any)
    vi.clearAllMocks()
  })
})
```

**Pattern from `cache.test.ts`:**
```typescript
describe('CacheService - TTL and Expiration', () => {
  let cache: CacheService

  beforeEach(() => {
    const config: CacheConfig = {
      ttl: 1, // 1 second TTL for testing
      kvEnabled: false,
      memoryEnabled: true,
      namespace: 'test',
      invalidateOn: [],
      version: 'v1'
    }
    cache = createCacheService(config)
  })
})
```

## Imports in Tests

**Standard pattern from `src/__tests__/middleware/auth.test.ts`:**
```typescript
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { AuthManager, requireAuth, requireRole, optionalAuth } from '../../middleware/auth'
import { Context, Next } from 'hono'
```

**Test utilities import:**
- `describe` - Group tests
- `it` - Define individual test
- `expect` - Assertions
- `beforeEach` - Setup before each test
- `vi` - Mock/spy utilities

## Mocking Patterns

### Mock Database Functions

**Factory function for database mocks** (`src/services/settings.test.ts`):
```typescript
function createMockDb() {
  const mockPrepare = vi.fn()
  const mockBind = vi.fn()
  const mockFirst = vi.fn()
  const mockAll = vi.fn()
  const mockRun = vi.fn()

  const chainable = {
    bind: mockBind.mockReturnThis(),
    first: mockFirst,
    all: mockAll,
    run: mockRun
  }

  mockPrepare.mockReturnValue(chainable)

  return {
    prepare: mockPrepare,
    _mocks: {
      prepare: mockPrepare,
      bind: mockBind,
      first: mockFirst,
      all: mockAll,
      run: mockRun
    }
  }
}
```

**Usage in tests:**
```typescript
mockDb._mocks.first.mockResolvedValue(null)

const result = await settingsService.getSetting('general', 'nonexistent')

expect(result).toBeNull()
expect(mockDb._mocks.prepare).toHaveBeenCalledWith(
  'SELECT value FROM settings WHERE category = ? AND key = ?'
)
expect(mockDb._mocks.bind).toHaveBeenCalledWith('general', 'nonexistent')
```

### Mock Context (Hono)

**Mock Hono context for middleware** (`src/__tests__/middleware/auth.test.ts`):
```typescript
let mockContext: any
let mockNext: Next

beforeEach(() => {
  mockNext = vi.fn()
  mockContext = {
    req: {
      header: vi.fn(),
      raw: {
        headers: new Headers()
      }
    },
    set: vi.fn(),
    json: vi.fn().mockReturnValue({ error: 'Authentication required' }),
    redirect: vi.fn().mockReturnValue({ redirect: true }),
    env: {},
  }
})
```

**Mock different response behaviors:**
```typescript
mockContext.req.header.mockReturnValue(undefined)  // No header

mockContext.req.header.mockImplementation((name: string) => {
  if (name === 'Authorization') return 'Bearer invalid-token'
  return undefined
})

mockContext.req.header.mockImplementation((name: string) => {
  if (name === 'Accept') return 'text/html'
  return undefined
})
```

### Mock KV Cache

**Pattern from `cache.test.ts`:**
```typescript
let mockKv: any

beforeEach(async () => {
  mockKv = {
    get: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    list: vi.fn()
  }

  const config: CacheConfig = {
    ttl: 60,
    kvEnabled: true,
    memoryEnabled: true,
    namespace: 'kv-test',
    invalidateOn: [],
    version: 'v1'
  }
  cache = createCacheService(config, mockKv)
})
```

**Mock resolved values:**
```typescript
mockKv.get.mockResolvedValue(testValue)
mockKv.put.mockResolvedValue(undefined)
mockKv.delete.mockRejectedValue(new Error('KV delete error'))
```

## Test Patterns

### Basic Assertions

**Testing return values:**
```typescript
it('should return user when found', async () => {
  const result = await userService.getById('user-123')
  expect(result).toBeTruthy()
  expect(result?.id).toBe('user-123')
  expect(result?.email).toBe('test@example.com')
})

it('should return null when user does not exist', async () => {
  const result = await userService.getById('nonexistent')
  expect(result).toBeNull()
})
```

**Testing string values:**
```typescript
it('should escape HTML special characters', () => {
  expect(escapeHtml('<script>alert("xss")</script>'))
    .toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;')
})

it('should handle empty strings', () => {
  expect(escapeHtml('')).toBe('')
})
```

**Testing type and length:**
```typescript
it('should generate a valid JWT token', async () => {
  const token = await AuthManager.generateToken('user-123', 'test@example.com', 'admin')

  expect(token).toBeTruthy()
  expect(typeof token).toBe('string')
  expect(token.split('.')).toHaveLength(3)  // JWT has 3 parts
})
```

### Async Testing

**Pattern from `cache.test.ts`:**
```typescript
it('should expire entries after TTL', async () => {
  await cache.set('test:key', 'value')

  // Wait for expiration
  await new Promise(resolve => setTimeout(resolve, 1100))

  const result = await cache.get('test:key')
  expect(result).toBeNull()
})
```

### Error Testing

**Pattern from `cache.test.ts`:**
```typescript
it('should handle KV read errors gracefully', async () => {
  const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
  mockKv.get.mockRejectedValue(new Error('KV read error'))

  const result = await cache.get('test:key')

  expect(result).toBeNull()
  expect(consoleSpy).toHaveBeenCalledWith('KV cache read error:', expect.any(Error))

  consoleSpy.mockRestore()
})
```

**Pattern from `auth.test.ts`:**
```typescript
it('should reject request without token', async () => {
  mockContext.req.header.mockReturnValue(undefined)

  const middleware = requireAuth()
  await middleware(mockContext as Context, mockNext)

  expect(mockContext.json).toHaveBeenCalledWith(
    { error: 'Authentication required' },
    401
  )
  expect(mockNext).not.toHaveBeenCalled()
})
```

### Middleware Testing

**Test middleware execution flow:**
```typescript
it('should set user when valid token provided', async () => {
  const token = await AuthManager.generateToken('user-123', 'test@example.com', 'admin')

  mockContext.req.header.mockImplementation((name: string) => {
    if (name === 'Authorization') return `Bearer ${token}`
    return undefined
  })

  const middleware = requireAuth()
  await middleware(mockContext as Context, mockNext)

  expect(mockContext.set).toHaveBeenCalledWith('user', expect.objectContaining({
    userId: 'user-123',
    email: 'test@example.com',
    role: 'admin'
  }))
  expect(mockNext).toHaveBeenCalled()
})
```

### Cache Testing Patterns

**Test cache hit tracking:**
```typescript
it('should track cache hits', async () => {
  await cache.set('test:key', 'value')

  await cache.get('test:key') // Hit
  await cache.get('test:key') // Hit

  const stats = cache.getStats()
  expect(stats.memoryHits).toBe(2)
})
```

**Test pattern invalidation:**
```typescript
it('should invalidate entries matching pattern', async () => {
  await cache.set('content:post:1', 'value1')
  await cache.set('content:post:2', 'value2')
  await cache.set('content:page:1', 'value3')

  const count = await cache.invalidate('content:post:*')

  expect(count).toBe(2)
  expect(await cache.get('content:post:1')).toBeNull()
  expect(await cache.get('content:post:2')).toBeNull()
  expect(await cache.get('content:page:1')).toBe('value3')
})
```

## Coverage Configuration

**Configured in `vitest.config.ts`:**

```typescript
coverage: {
  provider: 'v8',
  reporter: ['text', 'json', 'html'],
  include: ['src/**/*.{js,ts}'],
  exclude: [
    'src/**/*.{test,spec}.{js,ts}',
    'src/**/*.d.ts',
    'src/scripts/**',
    'src/templates/**',
    'src/routes/**',
    'src/plugins/**',
    'src/collections/**',
    'src/index.ts',
    'src/db/index.ts',
    'src/types/**',
    // ... and more
  ],
  thresholds: {
    global: {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90
    }
  }
}
```

**Coverage thresholds:** 90% for all metrics (branches, functions, lines, statements)

**Excluded from coverage:**
- Test files themselves
- Type definitions (`.d.ts`)
- Scripts
- Templates
- Route definitions
- Plugin definitions
- Collection definitions
- Entry points and database configuration
- Middleware bootstrap and logging files
- Services like migrations, logger, automation, webhooks

**Generate coverage:**
```bash
npm run test:cov
```

**Coverage output:**
- `text` - Console output
- `json` - Machine-readable format
- `html` - Interactive HTML report

## Test Data and Factories

### Mock Data Objects

**Pattern from `auth.test.ts`:**
```typescript
const token = await AuthManager.generateToken('user-123', 'test@example.com', 'admin')

const cachedPayload = {
  userId: 'cached-user',
  email: 'cached@example.com',
  role: 'admin',
  exp: Math.floor(Date.now() / 1000) + 3600,
  iat: Math.floor(Date.now() / 1000)
}
```

### Factory Functions

**Mock database factory:**
```typescript
function createMockDb() {
  const mockPrepare = vi.fn()
  const mockBind = vi.fn()
  // ... mock setup
  return {
    prepare: mockPrepare,
    _mocks: { prepare, bind, first, all, run }
  }
}
```

**Service factory in tests:**
```typescript
const config: CacheConfig = {
  ttl: 1,
  kvEnabled: false,
  memoryEnabled: true,
  namespace: 'test',
  invalidateOn: [],
  version: 'v1'
}
cache = createCacheService(config)
```

## Test Types Observed

### Unit Tests

**Scope:** Individual functions/methods in isolation

Examples:
- `escapeHtml()` function in `sanitize.test.ts`
- `sanitizeInput()` function in `sanitize.test.ts`
- `AuthManager.generateToken()` in `auth.test.ts`
- `AuthManager.verifyPassword()` in `auth.test.ts`
- Cache utility functions like `generateCacheKey()`, `parseCacheKey()`

**Pattern:** Call function, assert output, verify side effects

### Integration Tests

**Scope:** Multiple components working together

Examples:
- Middleware with mocked Hono context (`auth.test.ts`)
- Cache service with mocked KV storage (`cache.test.ts`)
- Settings service with mocked database (`settings.test.ts`)

**Pattern:** Set up environment, execute workflow, verify interactions

## Common Test Scenarios

### Testing Null/Missing Values

```typescript
it('should return null when setting does not exist', async () => {
  mockDb._mocks.first.mockResolvedValue(null)
  const result = await settingsService.getSetting('general', 'nonexistent')
  expect(result).toBeNull()
})

it('should return null for non-existent key', async () => {
  const result = await cache.get('non-existent')
  expect(result).toBeNull()
})
```

### Testing Boolean Conditions

```typescript
it('should verify correct password', async () => {
  const password = 'test-password-123'
  const hash = await AuthManager.hashPassword(password)
  const isValid = await AuthManager.verifyPassword(password, hash)
  expect(isValid).toBe(true)
})

it('should reject incorrect password', async () => {
  const hash = await AuthManager.hashPassword('test-password-123')
  const isValid = await AuthManager.verifyPassword('wrong-password', hash)
  expect(isValid).toBe(false)
})
```

### Testing Consistency

```typescript
it('should hash same password consistently', async () => {
  const password = 'test-password-123'
  const hash1 = await AuthManager.hashPassword(password)
  const hash2 = await AuthManager.hashPassword(password)
  expect(hash1).toBe(hash2)
})

it('should hash query parameters consistently', () => {
  const params1 = { limit: 10, offset: 0, sort: 'asc' }
  const params2 = { offset: 0, limit: 10, sort: 'asc' }
  const hash1 = hashQueryParams(params1)
  const hash2 = hashQueryParams(params2)
  expect(hash1).toBe(hash2) // Order shouldn't matter
})
```

### Testing Immutability

```typescript
it('should create new object without mutating original', () => {
  const input = {
    title: '<script>',
    description: '<b>test</b>',
  }
  const result = sanitizeObject(input, ['title'])
  expect(result).not.toBe(input) // Different object reference
  expect(input.title).toBe('<script>') // Original unchanged
})
```

## Notable Test Characteristics

**No E2E tests in unit test files:** E2E tests are separate in `tests/` directory using Playwright

**Spy on console for error testing:**
```typescript
const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
// ... test code
expect(consoleSpy).toHaveBeenCalledWith('Expected error', expect.any(Error))
consoleSpy.mockRestore()
```

**Test collection stats and metrics:**
```typescript
const stats = cache.getStats()
expect(stats.memoryHits).toBe(2)
expect(stats.memoryMisses).toBe(1)
expect(stats.hitRate).toBe(66.66666666666667)
expect(stats.totalRequests).toBe(3)
expect(stats.entryCount).toBe(3)
```

---

*Testing analysis: 2026-01-30*
