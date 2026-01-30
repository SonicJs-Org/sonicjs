# Coding Conventions

**Analysis Date:** 2026-01-30

## Naming Patterns

### Files

**Pattern:** kebab-case

Examples:
- `user-service.ts` - Service classes
- `auth.middleware.ts` - Middleware functions
- `auth-validation.ts` - Service utilities
- `plugin-middleware.ts` - Plugin-related code
- `cache.test.ts` - Test files

**Rule:** All file names use lowercase with hyphens. No camelCase, PascalCase, or snake_case for filenames.

### Functions

**Pattern:** camelCase

Examples from codebase:
- `getUserById()` - Query/getter functions
- `sanitizeInput()` - Utility functions
- `isRegistrationEnabled()` - Boolean queries
- `generateToken()` - Generator functions
- `verifyToken()` - Verification functions
- `createMockDb()` - Factory functions

**Rule:** Use descriptive verb-noun combinations. Prefix boolean functions with `is`, `has`, `can`, `should`.

### Variables and Constants

**Variables:** camelCase
```typescript
const userData = await getUserById(userId)
const isValidEmail = validateEmail(email)
let itemCount = 0
const token = getCookie(c, 'auth_token')
```

**Constants:** SCREAMING_SNAKE_CASE
```typescript
const JWT_SECRET = 'your-super-secret-jwt-key-change-in-production'
const CACHE_TTL = 300
const MAX_RETRIES = 3
const DEFAULT_ROLE = 'user'
```

### Types and Classes

**Pattern:** PascalCase

Examples from codebase:
- `AuthManager` - Service classes
- `JWTPayload` - Type definitions
- `CacheService` - Service classes
- `FieldDefinition` - Type definitions

**Interfaces:** PascalCase (no `I` prefix)
```typescript
export interface AuthSettings {
  enablePasswordLogin?: boolean
  enableOAuthLogin?: boolean
  requireEmailVerification?: boolean
}
```

## Import Organization

**Order (enforce by convention):**

1. Node.js built-in modules (`fs`, `path`, etc.)
2. Third-party packages (`hono`, `zod`, `drizzle-orm`, etc.)
3. Type imports (using `import type`)
4. Internal absolute imports (using `@/` path alias)
5. Relative imports (using `./` or `../`)

**Example from codebase (`src/middleware/auth.ts`):**
```typescript
import { sign, verify } from 'hono/jwt'    // Third-party
import { Context, Next } from 'hono'       // Third-party
import { getCookie, setCookie } from 'hono/cookie'  // Third-party

type JWTPayload = {                         // Type definition
  userId: string
  email: string
  role: string
  exp: number
  iat: number
}
```

**Example from tests (`src/__tests__/middleware/auth.test.ts`):**
```typescript
import { describe, it, expect, beforeEach, vi } from 'vitest'  // Test framework
import { AuthManager, requireAuth, requireRole, optionalAuth } from '../../middleware/auth'  // Relative
import { Context, Next } from 'hono'  // Third-party
```

## Code Style

### TypeScript Configuration

**Strict mode enabled** - `strict: true` in `tsconfig.json`

Key strictness settings applied:
- `noUncheckedIndexedAccess: true` - Prevents undefined array access
- `noImplicitReturns: true` - Requires explicit return in all code paths
- `noFallthroughCasesInSwitch: true` - Prevents switch fall-through bugs
- `noUncheckedSideEffectImports: true` - Prevents side effect imports
- `forceConsistentCasingInFileNames: true` - Consistent file naming

### Type Annotations

**Always use explicit type annotations**

Correct:
```typescript
function getUser(id: string): Promise<User | null> {
  // ...
}

const userData: User = await getUserById(userId)
const isValid: boolean = validateEmail(email)
```

Incorrect:
```typescript
function getUser(id): any {  // Missing types
  // ...
}

const userData = await getUserById(userId)  // Missing type
```

### Async/Await

**Prefer async/await over .then() chains**

Correct:
```typescript
async function fetchData() {
  try {
    const result = await api.getData()
    return result
  } catch (error) {
    logger.error('Failed to fetch data', error)
    throw error
  }
}
```

Avoid:
```typescript
function fetchData() {
  return api.getData()
    .then(result => result)
    .catch(error => {
      logger.error(error)
      throw error
    })
}
```

### Comments and Documentation

**JSDoc for public APIs:**
```typescript
/**
 * Check if user registration is enabled in the auth plugin settings
 * @param db - D1 database instance
 * @returns true if registration is enabled, false if disabled
 */
export async function isRegistrationEnabled(db: D1Database): Promise<boolean> {
  // ...
}
```

**Inline comments explain "why", not "what":**

Good:
```typescript
// Cache for 5 minutes to reduce database load during peak hours
const CACHE_TTL = 300
```

Bad:
```typescript
// Set cache TTL to 300 seconds
const CACHE_TTL = 300
```

## Error Handling

### Strategy

**Use try/catch blocks** with meaningful error logging:
```typescript
try {
  const payload = await AuthManager.verifyToken(token)
  if (!payload) {
    return c.json({ error: 'Invalid or expired token' }, 401)
  }
  c.set('user', payload)
  return await next()
} catch (error) {
  console.error('Auth middleware error:', error)
  const acceptHeader = c.req.header('Accept') || ''
  if (acceptHeader.includes('text/html')) {
    return c.redirect('/auth/login?error=Authentication failed, please login again')
  }
  return c.json({ error: 'Authentication failed' }, 401)
}
```

### Custom Error Classes

When relevant, use descriptive error classes. Example patterns in codebase:

```typescript
// Return null for "not found" scenarios
export async function getSetting(db: D1Database): Setting | null {
  try {
    const result = await db.prepare('SELECT value FROM settings ...').first()
    return result || null
  } catch {
    return null
  }
}

// Return false for validation failures
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const passwordHash = await this.hashPassword(password)
  return passwordHash === hash
}

// Throw for exceptional cases
export function setAuthCookie(c: Context, token: string, options?: {...}): void {
  setCookie(c, 'auth_token', token, {
    httpOnly: options?.httpOnly ?? true,
    secure: options?.secure ?? true,
  })
}
```

### Error Logging

**Always log errors with context:**
```typescript
logger.error('Failed to fetch data', { id, error })
console.error('Auth middleware error:', error)
console.error('KV cache write error:', error)
```

## Module Design

### Exports

**Named exports for functions and types:**
```typescript
export function isRegistrationEnabled(db: D1Database): Promise<boolean>
export async function checkAdminUserExists(db: D1Database): Promise<boolean>
export interface AuthSettings { /* ... */ }
export type JWTPayload = { /* ... */ }
```

**Class exports:**
```typescript
export class AuthManager {
  static async generateToken(...): Promise<string>
  static async verifyToken(...): Promise<JWTPayload | null>
}
```

### Middleware Factories

**Middleware are factory functions returning handlers:**
```typescript
export const requireAuth = () => {
  return async (c: Context, next: Next) => {
    // middleware logic
  }
}

export const requireRole = (requiredRole: string | string[]) => {
  return async (c: Context, next: Next) => {
    // middleware logic
  }
}
```

## Service Patterns

### Database Operations

**Use try/catch with null returns for optional results:**
```typescript
export async function isFirstUserRegistration(db: D1Database): Promise<boolean> {
  try {
    const result = await db.prepare('SELECT COUNT(*) as count FROM users').first() as { count: number } | null
    return result?.count === 0
  } catch {
    return false
  }
}
```

### Caching Patterns

**Cache keys follow namespace convention:**
```typescript
const cacheKey = `auth:${token.substring(0, 20)}`  // Namespaced with prefix
```

**Cache hit/miss tracking:**
```typescript
const stats = cache.getStats()
// Returns: { memoryHits, memoryMisses, hitRate, totalRequests, entryCount, ... }
```

## Testing Conventions

### Describe Blocks

Organize tests with nested `describe` blocks:
```typescript
describe('AuthManager', () => {
  describe('generateToken', () => {
    it('should generate a valid JWT token', async () => { ... })
    it('should generate unique tokens for different users', async () => { ... })
  })

  describe('verifyToken', () => {
    it('should verify a valid token', async () => { ... })
    it('should return null for invalid token', async () => { ... })
  })
})
```

### Test Naming

Use descriptive names that explain the scenario:
```typescript
it('should return user when found', async () => {})
it('should return null when user does not exist', async () => {})
it('should throw error when database connection fails', async () => {})
it('should reject request without token', async () => {})
it('should accept request with valid token', async () => {})
```

### Mocking Pattern

**Use `vi` from vitest for mocking:**
```typescript
const mockContext = {
  req: {
    header: vi.fn(),
  },
  set: vi.fn(),
  json: vi.fn().mockReturnValue({ error: 'Authentication required' }),
  redirect: vi.fn().mockReturnValue({ redirect: true }),
}

mockContext.req.header.mockReturnValue(undefined)
mockContext.req.header.mockImplementation((name: string) => {
  if (name === 'Authorization') return 'Bearer invalid-token'
  return undefined
})
```

## Formatting

### Line Length

**TypeScript compiler configured:**
- Target: ES2020
- Module: ESNext
- Declaration maps enabled for debugging

### Semicolons and Quotes

**From CODING_STANDARDS.md configuration:**
- Semicolons: Not required (prettier config: `semi: false`)
- Quotes: Single quotes preferred (`singleQuote: true`)
- Tab width: 2 spaces
- Trailing commas: ES5 style

### ESLint

**Type-checking replaces linting:**
```bash
npm run type-check  # Runs tsc --noEmit
```

**Pre-commit hooks enforce:**
- Type checking via `tsc --noEmit`
- Code formatting via Prettier (automatic)

---

*Convention analysis: 2026-01-30*
