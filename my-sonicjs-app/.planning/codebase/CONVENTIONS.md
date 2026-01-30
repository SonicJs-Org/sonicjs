# Coding Conventions

**Analysis Date:** 2026-01-30

## Naming Patterns

**Files:**
- Source files: lowercase with hyphens for multi-word names (e.g., `plugin-manager.ts`, `cache-warming.ts`)
- Test files: suffix with `.test.ts` or `.spec.ts` (e.g., `auth.test.ts`, `plugin-builder.test.ts`)
- Service files: named with service intent (e.g., `logger.ts`, `migrations.ts`, `collection-sync.ts`)
- Plugin directories: kebab-case for namespacing (e.g., `email-templates-plugin`, `database-tools-plugin`)

**Functions:**
- Regular functions: camelCase (e.g., `generateToken`, `verifyPassword`, `sanitizeInput`)
- Handler/middleware functions: often suffixed with descriptive names (e.g., `requireAuth()`, `bootstrapMiddleware()`)
- Factory/builder methods: `create*` or `*Builder` pattern (e.g., `PluginBuilder.create()`, `createMockDb()`)
- Async functions: no special naming convention, use `async` keyword

**Variables:**
- Local variables and constants: camelCase by default
- Constants: can be UPPER_CASE for static config (e.g., `JWT_SECRET`, `CACHE_CONFIGS`)
- Schema/type constants: PascalCase when exported (e.g., `PluginConfigSchema`)
- Configuration objects: camelCase (e.g., `logConfig`, `cacheConfig`)

**Types and Interfaces:**
- TypeScript interfaces: PascalCase (e.g., `JWTPayload`, `LogEntry`, `PluginRegistry`)
- Type aliases: PascalCase (e.g., `LogLevel`, `LogCategory`, `HookHandler`)
- Enum members: PascalCase or UPPER_CASE (e.g., `enum LogLevel { Debug, Info, Warn, Error }`)

**Classes:**
- Classes: PascalCase (e.g., `AuthManager`, `Logger`, `PluginManager`, `PluginBuilder`)
- Implementation classes: often `*Impl` suffix (e.g., `PluginRegistryImpl`, `HookSystemImpl`)

## Code Style

**Formatting:**
- No explicit formatter configured (Prettier not detected in eslint config)
- TypeScript compiler is used for type checking via `tsc --noEmit`
- Code appears to follow standard JavaScript/TypeScript formatting patterns

**Linting:**
- ESLint configured with TypeScript plugin (`@typescript-eslint/eslint-plugin`)
- Config file: `/Users/andrewhaas/Projects/SonicJS/sonicjs/packages/core/eslint.config.js` (ESLint flat config format)
- Key rules enforced:
  - `@typescript-eslint/naming-convention`: Strict naming conventions per category
  - `@typescript-eslint/no-unused-vars`: Warns on unused variables (allows leading underscore prefix `_varName` to ignore)
  - `@typescript-eslint/no-explicit-any`: Warns on `any` type usage

**Naming Convention Details from ESLint:**
- **Default**: camelCase with optional leading/trailing underscores
- **Variables**: camelCase, UPPER_CASE, or PascalCase (allows schema constants like `PluginConfigSchema`)
- **Functions**: camelCase or PascalCase (for React components)
- **Parameters**: camelCase
- **Object literal properties**: No format restriction (allows HTTP headers, snake_case DB columns, numeric keys)
- **Type properties**: camelCase, PascalCase, UPPER_CASE, snake_case (flexibility for API responses)
- **Classes/Interfaces/Types**: PascalCase
- **Enum members**: PascalCase or UPPER_CASE

## Import Organization

**Order:**
1. Framework imports (Hono, zod)
2. Type imports from relative paths
3. Utility/service imports from relative paths
4. Database and third-party service imports

**Example from codebase:**
```typescript
import { sign, verify } from 'hono/jwt'
import { Context, Next } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'
```

**Path Aliases:**
- None explicitly detected in codebase
- Uses relative imports throughout (e.g., `from '../../middleware/auth'`, `from '../types'`)
- Import structure suggests flat hierarchy awareness

## Error Handling

**Patterns:**
- Try-catch blocks for async operations that can fail
- Null returns for validation failures (e.g., `verifyToken()` returns `null` on invalid token)
- Throwing `Error` instances for unrecoverable states (e.g., plugin validation failures)
- Console logging for error context (e.g., `console.error('Token verification failed:', error)`)

**Example from `plugin-registry.ts`:**
```typescript
try {
  // operation
} catch (error) {
  const errorMessage = error instanceof Error ? error.message : String(error)
  throw new Error(`Failed to activate plugin ${name}: ${errorMessage}`)
}
```

**Example from `auth.ts`:**
```typescript
try {
  const payload = await verify(token, JWT_SECRET, 'HS256') as JWTPayload
  if (payload.exp < Math.floor(Date.now() / 1000)) {
    return null  // Token expired
  }
  return payload
} catch (error) {
  console.error('Token verification failed:', error)
  return null
}
```

## Logging

**Framework:** Console methods (`console.info`, `console.warn`, `console.error`)

**Also:** Custom `Logger` service with structured logging support
- Location: `src/services/logger.ts`
- Provides: Structured logging with categories, levels, context
- Log levels: `debug`, `info`, `warn`, `error`, `fatal`
- Log categories: `auth`, `api`, `workflow`, `plugin`, `media`, `system`, `security`, `error`

**Patterns:**
- Informational messages: `console.info('message')`
- Warnings: `console.warn('Plugin dependency error')`
- Errors with context: `console.error('Failed to load plugin:', error)`
- No special log formatting applied at this level

## Comments

**When to Comment:**
- File headers: Block comment explaining module purpose (seen in `plugin-manager.ts`, `sanitize.ts`)
- Public methods: JSDoc comments for exported functions and classes
- Complex logic: Brief explanations for non-obvious algorithms

**JSDoc/TSDoc:**
- Used for public SDK methods (e.g., `PluginBuilder` class)
- Format: `/** description */` for single-line or block format
- Includes `@param`, `@returns`, `@example`, `@beta` tags
- Example from `plugin-builder.ts`:
```typescript
/**
 * Fluent builder for creating SonicJS plugins.
 *
 * @beta This API is in beta and may change in future releases.
 *
 * @example
 * ```typescript
 * const plugin = PluginBuilder.create({ ... }).addRoute(...).build()
 * ```
 */
```

## Function Design

**Size:**
- Functions are generally focused on single responsibilities
- Methods in plugin manager: typically 10-50 lines
- Factory methods: 5-15 lines

**Parameters:**
- Async functions: generally take specific typed parameters (e.g., `generateToken(userId: string, email: string, role: string)`)
- Builder/fluent APIs: return `this` for method chaining
- Configuration: often accept options object for flexibility

**Return Values:**
- Async operations: `Promise<T>` or `Promise<void>`
- Validation: returns `null` for failure cases vs throwing for critical errors
- Builder pattern: returns `this` for chaining
- Queries: returns typed results or arrays

**Example from `PluginBuilder`:**
```typescript
addRoute(path: string, handler: Hono, options?: {
  description?: string
  requiresAuth?: boolean
  roles?: string[]
  priority?: number
}): PluginBuilder {
  // implementation
  return this
}
```

## Module Design

**Exports:**
- Named exports for services, classes, interfaces
- Default exports not commonly used
- Re-export pattern seen in `middleware/index.ts` for public API

**Barrel Files:**
- Used in `types/index.ts` to re-export all type definitions
- Pattern: `export * from './plugin'`, `export * from './collection-config'`
- Centralizes public API surface

**Example from types barrel:**
```typescript
export * from './plugin'
export * from './collection-config'
export * from './plugin-manifest'
export * from './telemetry'
```

## Async/Await Pattern

- Consistently used throughout for asynchronous operations
- No callback-based patterns observed
- Promises wrapped with `async/await` for readability
- Error handling paired with try-catch blocks

## Type Safety

- TypeScript strict mode enforced via ESLint rules
- Generic types used in service patterns (e.g., `Logger<T>`, `Cache<T>`)
- Zod used for runtime schema validation
- Type assertions minimal, used where framework requires (e.g., `as JWTPayload`)

---

*Convention analysis: 2026-01-30*
