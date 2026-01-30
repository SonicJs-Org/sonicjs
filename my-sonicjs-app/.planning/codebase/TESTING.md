# Testing Patterns

**Analysis Date:** 2026-01-30

## Test Framework

**Runner:**
- Vitest 2.1.8
- Config files:
  - Core package: `/Users/andrewhaas/Projects/SonicJS/sonicjs/packages/core/vitest.config.ts`
  - Root: `/Users/andrewhaas/Projects/SonicJS/sonicjs/vitest.config.ts`
- Environment: Node.js (no browser/DOM testing)
- Global test APIs enabled (`globals: true`)

**Assertion Library:**
- Vitest built-in assertions via `expect()`
- No separate assertion library needed

**Run Commands:**
```bash
npm run test              # Run all tests once
npm run test:watch       # Watch mode for development
npm run test:coverage    # Coverage report (inferred from vitest config)
```

## Test File Organization

**Location:**
- Co-located pattern: Tests placed next to source code
- Alternative: Centralized in `__tests__/` directory
- Root tests folder: `/Users/andrewhaas/Projects/SonicJS/sonicjs/packages/core/src/__tests__/`

**Naming:**
- `.test.ts` suffix (e.g., `auth.test.ts`, `plugin-builder.test.ts`)
- `.spec.ts` also supported but `.test.ts` is standard in this codebase

**Structure Examples:**
```
src/
├── middleware/
│   ├── auth.ts
│   ├── auth.test.ts
│   ├── bootstrap.ts
│   └── bootstrap.test.ts
├── plugins/
│   ├── plugin-manager.ts
│   ├── cache/
│   │   ├── services/
│   │   │   ├── cache.ts
│   │   │   └── cache-config.ts
│   │   └── tests/
│   │       ├── cache.test.ts
│   │       ├── cache-warming.test.ts
│   │       └── cache-invalidation.test.ts
└── __tests__/
    ├── middleware/
    ├── plugins/
    └── utils/
```

## Test Structure

**Suite Organization:**
```typescript
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'

describe('SuiteName', () => {
  describe('nested context', () => {
    it('should do something', () => {
      expect(result).toBe(expected)
    })
  })
})
```

**Setup/Teardown:**
```typescript
beforeEach(() => {
  // Run before each test
  // Reset mocks, create fresh instances
  vi.clearAllMocks()
})

afterEach(() => {
  // Run after each test
  // Cleanup
})
```

**Example from `auth.test.ts`:**
```typescript
describe('AuthManager', () => {
  describe('generateToken', () => {
    it('should generate a valid JWT token', async () => {
      const token = await AuthManager.generateToken('user-123', 'test@example.com', 'admin')

      expect(token).toBeTruthy()
      expect(typeof token).toBe('string')
      expect(token.split('.')).toHaveLength(3) // JWT has 3 parts
    })

    it('should generate unique tokens for different users', async () => {
      const token1 = await AuthManager.generateToken('user-1', 'user1@example.com', 'user')
      const token2 = await AuthManager.generateToken('user-2', 'user2@example.com', 'user')

      expect(token1).not.toBe(token2)
    })
  })
})
```

## Mocking

**Framework:** Vitest's `vi` module
- Uses `vi.fn()` for function mocks
- Uses `vi.mock()` for module mocking
- Includes `vi.spyOn()` for spying on methods

**Patterns:**

**Function Mocks:**
```typescript
const mockFirst = vi.fn()
const mockAll = vi.fn()

mockFirst.mockResolvedValue({ status: 'active' })  // For async returns
mockAll.mockReturnValue({ results: [] })            // For sync returns
```

**Module Mocks (example from `bootstrap.test.ts`):**
```typescript
vi.mock('../services/collection-sync', () => ({
  syncCollections: vi.fn().mockResolvedValue([])
}))

vi.mock('../services/migrations', () => {
  const mockRunPendingMigrations = vi.fn().mockResolvedValue(undefined)
  return {
    MigrationService: vi.fn().mockImplementation(function() {
      this.runPendingMigrations = mockRunPendingMigrations
      return this
    })
  }
})
```

**Database Mocks (factory pattern):**
```typescript
function createMockDb() {
  const mockPrepare = vi.fn()
  const mockBind = vi.fn()
  const mockFirst = vi.fn()
  const mockAll = vi.fn()

  const chainable = {
    bind: mockBind.mockReturnThis(),
    first: mockFirst,
    all: mockAll
  }

  mockPrepare.mockReturnValue(chainable)

  return {
    prepare: mockPrepare,
    _mocks: {
      prepare: mockPrepare,
      bind: mockBind,
      first: mockFirst,
      all: mockAll
    }
  }
}
```

**Assertion/Spy Usage:**
```typescript
const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

// Later verify it was called
expect(consoleSpy).toHaveBeenCalledWith(
  '[isPluginActive] Error checking plugin status for my-plugin:',
  expect.any(Error)
)
```

**What to Mock:**
- External dependencies (database, services)
- Module-level imports that are side-effectful
- File system operations
- API calls
- Time-based operations (use `vi.useFakeTimers()`)

**What NOT to Mock:**
- The code under test itself
- Pure utility functions
- Standard library modules (usually)
- Often keep authentication/validation real in integration tests

## Fixtures and Factories

**Test Data Patterns:**

Simple inline objects:
```typescript
const input = {
  title: '<script>alert()</script>',
  count: 42,
  active: true,
}
```

Schema/validation testing:
```typescript
const schema = PluginHelpers.createSchema([
  { name: 'title', type: 'string' },
  { name: 'subtitle', type: 'string', optional: true }
])

expect(schema.parse({ title: 'Hello' })).toEqual({ title: 'Hello' })
```

**Location:**
- Fixtures typically created inline within test suites
- Factory functions at top of test files (e.g., `createMockDb()`, `createMockEnv()`)
- No centralized fixture directory detected (pattern suggests inline factories preferred)

## Coverage

**Requirements:**
- Global thresholds enforced at 90% (from `/Users/andrewhaas/Projects/SonicJS/sonicjs/packages/core/vitest.config.ts`)
  - branches: 90%
  - functions: 90%
  - lines: 90%
  - statements: 90%

**View Coverage:**
```bash
npm run test -- --coverage
# Or configure vitest coverage via:
# vitest run --coverage
```

**Provider:** V8 (built-in coverage provider)

**Coverage Reporters:**
- text (console output)
- json (machine-readable)
- html (visual reports)

**Exclusions from Coverage (core package):**
- `node_modules/`, `dist/`, `src/__tests__/`, `**/*.d.ts`, `**/*.config.*`, `**/mockData`
- Also excludes routes, plugins, collections, templates, services like migrations, logger, webhooks, etc.

## Test Types

**Unit Tests:**
- Scope: Individual functions and classes
- Approach: Isolated testing with mocks for dependencies
- Example: `auth.test.ts` tests `AuthManager` methods individually
- Pattern: Direct function calls with assertions

**Integration Tests:**
- Scope: Multiple components working together
- Approach: Real implementations where practical, mocked external services
- Example: `cache.test.ts` tests cache service with configuration and utilities
- Pattern: Tests behavior of system pieces collaborating

**E2E Tests:**
- Framework: Not detected in codebase
- Status: Not currently used
- Would use: Likely Playwright or similar if implemented

## Common Patterns

**Async Testing:**
```typescript
it('should verify a valid token', async () => {
  const userId = 'user-123'
  const email = 'test@example.com'
  const role = 'admin'

  const token = await AuthManager.generateToken(userId, email, role)
  const payload = await AuthManager.verifyToken(token)

  expect(payload?.userId).toBe(userId)
  expect(payload?.email).toBe(email)
  expect(payload?.role).toBe(role)
})
```

**Error Testing (negative cases):**
```typescript
it('should return null for invalid token', async () => {
  const payload = await AuthManager.verifyToken('invalid.token.here')
  expect(payload).toBeNull()
})

it('should throw when plugin validation fails', async () => {
  const plugin = { /* invalid plugin */ }

  await expect(async () => {
    await registry.register(plugin)
  }).rejects.toThrow('Plugin validation failed')
})
```

**Validation Testing (schemas):**
```typescript
it('applies min length validation', () => {
  const schema = PluginHelpers.createSchema([
    { name: 'title', type: 'string', validation: { min: 3 } }
  ])

  expect(schema.parse({ title: 'Hello' })).toEqual({ title: 'Hello' })
  expect(() => schema.parse({ title: 'Hi' })).toThrow()
})
```

**Database/Query Testing:**
```typescript
it('should check plugin status via database', async () => {
  mockDb._mocks.first.mockResolvedValue({ status: 'active' })

  const result = await isPluginActive(mockDb as any, 'my-plugin')

  expect(result).toBe(true)
  expect(mockDb._mocks.prepare).toHaveBeenCalledWith(
    'SELECT status FROM plugins WHERE id = ?'
  )
  expect(mockDb._mocks.bind).toHaveBeenCalledWith('my-plugin')
})
```

**Spy/Mock Verification:**
```typescript
const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
mockDb._mocks.first.mockRejectedValue(new Error('DB error'))

await isPluginActive(mockDb as any, 'my-plugin')

expect(consoleSpy).toHaveBeenCalledWith(
  '[isPluginActive] Error checking plugin status for my-plugin:',
  expect.any(Error)
)
```

## Test Count & Coverage Status

**Total test files:** 53+ across the core package
**Test organization:**
- 30+ in `src/__tests__/` (centralized)
- 20+ co-located with source (e.g., `middleware/`, `plugins/cache/tests/`)

**Coverage status:** Targeting 90% thresholds (as of config)

---

*Testing analysis: 2026-01-30*
