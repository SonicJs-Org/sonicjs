# Phase 5: API Endpoints - Research

**Researched:** 2026-01-30
**Domain:** REST API design with Hono framework
**Confidence:** HIGH

## Summary

Phase 5 requires exposing the existing RedirectService CRUD operations (create, read, update, delete, list) through REST API endpoints for programmatic access by other plugins. The existing service layer is complete and robust, with validation, circular detection, and cache invalidation already implemented. The task is to create a thin API layer over these existing operations.

The standard approach is to use Hono's built-in routing with RESTful conventions: separate route files mounted via `app.route()`, JSON responses with consistent error formats, and optional Bearer token authentication for API access control. The existing admin routes provide a proven pattern to follow.

Key considerations include maintaining backward compatibility with existing functionality, providing consistent error responses following RFC 9457, and ensuring proper authentication for API endpoints (plugins calling APIs may need API keys or internal authentication bypass).

**Primary recommendation:** Create `/api/redirects` routes following REST conventions, reuse existing RedirectService methods, return RFC 9457-compliant JSON error responses, and implement Bearer auth middleware for external access while allowing internal plugin-to-plugin calls.

## Standard Stack

The established libraries/tools for this domain:

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Hono | ^4.11.7 | Web framework with routing | Already used, lightweight (14kb), built for Cloudflare Workers, excellent TypeScript support |
| @cloudflare/workers-types | ^4.20250620.0 | TypeScript types for Workers runtime | Required for D1Database types and Workers environment |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| Zod | ^3.25.67 | Schema validation | Already in project, use for validating API request bodies |
| hono/bearer-auth | (built-in) | Bearer token authentication | Protect API endpoints from unauthorized access |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Custom JSON responses | RFC 9457 Problem Details | RFC 9457 is standardized but adds verbosity; custom is simpler but less interoperable |
| Bearer auth | JWT middleware | JWT is more complex but supports stateless auth with claims; Bearer auth is simpler for API keys |
| Hono routing | Express.js | Express has more ecosystem but Hono is purpose-built for Workers edge runtime |

**Installation:**
```bash
# No new dependencies required
# Hono and Zod already installed
# Bearer auth is built into Hono
```

## Architecture Patterns

### Recommended Project Structure
```
src/plugins/redirect-management/
├── routes/
│   ├── admin.ts       # Existing admin UI routes
│   └── api.ts         # NEW: RESTful JSON API routes
├── services/
│   └── redirect.ts    # Existing service (no changes)
└── types.ts           # Existing types (may add API response types)
```

### Pattern 1: RESTful Resource Routes
**What:** Map HTTP methods to CRUD operations on `/api/redirects` resource
**When to use:** Standard for public/programmatic APIs
**Example:**
```typescript
// Source: Hono official docs + REST API conventions
const api = new Hono()

// List redirects with filtering
api.get('/', async (c) => {
  const filter: RedirectFilter = {
    isActive: c.req.query('isActive') === 'true' ? true :
              c.req.query('isActive') === 'false' ? false : undefined,
    statusCode: c.req.query('statusCode') ?
                parseInt(c.req.query('statusCode')) as StatusCode : undefined,
    matchType: c.req.query('matchType') ?
               parseInt(c.req.query('matchType')) as MatchType : undefined,
    search: c.req.query('search') || undefined,
    limit: parseInt(c.req.query('limit') || '50'),
    offset: parseInt(c.req.query('offset') || '0')
  }

  const service = new RedirectService(c.env.DB)
  const redirects = await service.list(filter)
  const total = await service.count(filter)

  return c.json({
    data: redirects,
    pagination: {
      limit: filter.limit,
      offset: filter.offset,
      total
    }
  })
})

// Get redirect by ID
api.get('/:id', async (c) => {
  const id = c.req.param('id')
  const service = new RedirectService(c.env.DB)
  const redirect = await service.getById(id)

  if (!redirect) {
    return c.json({
      type: 'about:blank',
      title: 'Not Found',
      status: 404,
      detail: `Redirect with ID ${id} not found`
    }, 404)
  }

  return c.json({ data: redirect })
})

// Create redirect
api.post('/', async (c) => {
  const body = await c.req.json()
  const userId = c.get('user')?.id || 'api'

  const service = new RedirectService(c.env.DB)
  const result = await service.create(body, userId)

  if (!result.success) {
    return c.json({
      type: 'about:blank',
      title: 'Bad Request',
      status: 400,
      detail: result.error
    }, 400)
  }

  return c.json({ data: result.redirect }, 201)
})

// Update redirect
api.put('/:id', async (c) => {
  const id = c.req.param('id')
  const body = await c.req.json()

  const service = new RedirectService(c.env.DB)
  const result = await service.update(id, body)

  if (!result.success) {
    const status = result.error === 'Redirect not found' ? 404 : 400
    return c.json({
      type: 'about:blank',
      title: status === 404 ? 'Not Found' : 'Bad Request',
      status,
      detail: result.error
    }, status)
  }

  return c.json({ data: result.redirect })
})

// Delete redirect
api.delete('/:id', async (c) => {
  const id = c.req.param('id')

  const service = new RedirectService(c.env.DB)
  const result = await service.delete(id)

  if (!result.success) {
    const status = result.error === 'Redirect not found' ? 404 : 400
    return c.json({
      type: 'about:blank',
      title: status === 404 ? 'Not Found' : 'Bad Request',
      status,
      detail: result.error
    }, status)
  }

  return c.json({ success: true }, 200)
})
```

### Pattern 2: Consistent Error Responses (RFC 9457 Lite)
**What:** Return standardized JSON error format across all endpoints
**When to use:** All error conditions in API routes
**Example:**
```typescript
// Source: RFC 9457 Problem Details specification
interface APIErrorResponse {
  type: string          // URI reference (use 'about:blank' for generic)
  title: string         // Short human-readable summary
  status: number        // HTTP status code
  detail: string        // Specific error message
  instance?: string     // URI reference to specific occurrence
}

// Helper function
function apiError(status: number, detail: string, title?: string): APIErrorResponse {
  const titles: Record<number, string> = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    409: 'Conflict',
    500: 'Internal Server Error'
  }

  return {
    type: 'about:blank',
    title: title || titles[status] || 'Error',
    status,
    detail
  }
}

// Usage
return c.json(apiError(400, 'Source URL is required'), 400)
```

### Pattern 3: Optional Bearer Authentication
**What:** Protect API endpoints with Bearer token middleware
**When to use:** When API is exposed externally; bypass for internal plugin calls
**Example:**
```typescript
// Source: Hono Bearer Auth docs
import { bearerAuth } from 'hono/bearer-auth'

// Option 1: Simple token validation
api.use('/api/redirects/*', bearerAuth({
  token: c.env.REDIRECTS_API_KEY || 'default-dev-key'
}))

// Option 2: Custom token validation (e.g., check database)
api.use('/api/redirects/*', bearerAuth({
  verifyToken: async (token, c) => {
    const db = c.env.DB
    const apiKey = await db.prepare(
      'SELECT id FROM api_keys WHERE key = ? AND is_active = 1'
    ).bind(token).first()
    return !!apiKey
  }
}))

// Option 3: Skip auth for internal calls
api.use('/api/redirects/*', async (c, next) => {
  // Check if request is from internal plugin (has user context)
  if (c.get('user')) {
    return next() // Skip Bearer auth for authenticated admin users
  }

  // Otherwise require Bearer token
  return bearerAuth({ token: c.env.REDIRECTS_API_KEY })(c, next)
})
```

### Pattern 4: Mount API Routes in Main App
**What:** Attach API routes to main application at `/api/redirects` path
**When to use:** During plugin initialization
**Example:**
```typescript
// Source: Hono routing docs + existing admin.ts pattern
// In plugin index.ts or main app routing
import { createRedirectApiRoutes } from './routes/api'

const apiRoutes = createRedirectApiRoutes()
app.route('/api/redirects', apiRoutes)
```

### Anti-Patterns to Avoid
- **Don't duplicate service logic in routes:** Routes should be thin wrappers calling RedirectService methods
- **Don't return HTML from API routes:** Always return JSON, even for errors
- **Don't use admin route patterns for API:** Admin routes use HTMX fragments; API routes use pure JSON
- **Don't version initially unless needed:** Start with `/api/redirects`, add `/v1/redirects` only when breaking changes require it
- **Don't return 200 OK with error payload:** Use proper HTTP status codes (4xx for client errors, 5xx for server errors)

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Request validation | Manual field checking | Zod schemas with c.req.json() validation | Zod provides type safety, automatic error messages, and complex validation rules |
| API authentication | Custom token checking | Hono's bearerAuth middleware | Built-in, tested, handles edge cases like malformed headers and timing attacks |
| Error response formatting | Ad-hoc error objects | RFC 9457 Problem Details pattern | Standardized, interoperable, expected by API consumers |
| Query parameter parsing | Manual parseInt/checks | Zod query schema validation | Type-safe, handles missing/invalid params, prevents injection |
| Rate limiting | Custom counters | Cloudflare Workers rate limiting API or hono-rate-limiter | Production-ready, distributed, prevents abuse |

**Key insight:** The service layer already handles all business logic (validation, circular detection, cache invalidation). API routes should ONLY handle HTTP concerns (parsing requests, formatting responses, authentication). Any logic duplication is a red flag.

## Common Pitfalls

### Pitfall 1: Inconsistent Error Response Format
**What goes wrong:** Mixing HTML error pages, plain text errors, and JSON errors in API routes
**Why it happens:** Copy-pasting from admin routes which return HTML fragments for HTMX
**How to avoid:** Always use `c.json()` in API routes, never `c.html()` or `c.text()` for errors
**Warning signs:** API clients receiving Content-Type: text/html; client parsing errors

### Pitfall 2: Missing Database Context
**What goes wrong:** Routes crash with "Database not available" when `c.env.DB` is undefined
**Why it happens:** Different context setup between local dev and production Workers
**How to avoid:** Use fallback pattern `c.env?.DB || c.get('db')` like admin routes do
**Warning signs:** Works in production but fails in tests/local dev (or vice versa)

### Pitfall 3: Authentication Blocking Internal Calls
**What goes wrong:** Plugins calling API endpoints get 401 Unauthorized despite being authenticated
**Why it happens:** Bearer auth middleware expects Authorization header even for internal requests
**How to avoid:** Check for user context first, only require Bearer token for external calls
**Warning signs:** QR code plugin can't create redirects; error logs show 401 on internal API calls

### Pitfall 4: Leaking Service Result Structure
**What goes wrong:** Returning RedirectOperationResult directly exposes internal structure
**Why it happens:** Service returns `{ success, redirect, error, warning }` but API should normalize
**How to avoid:** Transform service results into consistent API responses (data/error format)
**Warning signs:** API responses have both `redirect` and `data` fields; inconsistent structure

### Pitfall 5: Query Parameter Type Coercion
**What goes wrong:** `c.req.query('isActive')` returns string "true" which is always truthy in JavaScript
**Why it happens:** Query params are always strings; `if (isActive)` evaluates string "false" as true
**How to avoid:** Explicit string comparison: `isActive === 'true'` or use Zod schema validation
**Warning signs:** Filter by "inactive" returns all redirects; boolean filters don't work

### Pitfall 6: Missing Pagination Metadata
**What goes wrong:** List endpoint returns array without total count, breaking pagination UIs
**Why it happens:** Only calling `service.list()` without `service.count()`
**How to avoid:** Call both in parallel with `Promise.all([service.list(), service.count()])`
**Warning signs:** Client can't show "Page 1 of 5"; no way to know if more results exist

## Code Examples

Verified patterns from official sources:

### Complete API Route File Structure
```typescript
// Source: Existing admin.ts + Hono routing patterns
import { Hono } from 'hono'
import { bearerAuth } from 'hono/bearer-auth'
import { RedirectService } from '../services/redirect'
import type {
  RedirectFilter,
  CreateRedirectInput,
  UpdateRedirectInput,
  MatchType,
  StatusCode
} from '../types'

/**
 * RFC 9457 Problem Details error response
 */
interface APIError {
  type: string
  title: string
  status: number
  detail: string
  instance?: string
}

/**
 * Helper: Create RFC 9457-compliant error response
 */
function apiError(status: number, detail: string, title?: string): APIError {
  const titles: Record<number, string> = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    409: 'Conflict',
    500: 'Internal Server Error'
  }

  return {
    type: 'about:blank',
    title: title || titles[status] || 'Error',
    status,
    detail
  }
}

/**
 * Create API route handlers for redirect management
 */
export function createRedirectApiRoutes(): Hono {
  const api = new Hono()

  // Optional: Apply Bearer auth to all API routes
  // Skip if request has user context (internal plugin call)
  api.use('/*', async (c, next) => {
    // Internal authenticated calls bypass Bearer auth
    if (c.get('user')) {
      return next()
    }

    // External calls require API key
    const apiKey = c.env?.REDIRECTS_API_KEY
    if (apiKey) {
      return bearerAuth({ token: apiKey })(c, next)
    }

    // No API key configured - allow in dev, block in prod
    if (c.env?.ENVIRONMENT === 'production') {
      return c.json(apiError(401, 'API key required'), 401)
    }

    return next()
  })

  // GET /api/redirects - List redirects with filtering
  api.get('/', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json(apiError(503, 'Database unavailable'), 503)
      }

      // Parse query parameters
      const filter: RedirectFilter = {
        isActive: c.req.query('isActive') === 'true' ? true :
                  c.req.query('isActive') === 'false' ? false : undefined,
        statusCode: c.req.query('statusCode') ?
                    parseInt(c.req.query('statusCode')) as StatusCode : undefined,
        matchType: c.req.query('matchType') ?
                   parseInt(c.req.query('matchType')) as MatchType : undefined,
        search: c.req.query('search') || undefined,
        limit: parseInt(c.req.query('limit') || '50'),
        offset: parseInt(c.req.query('offset') || '0')
      }

      // Fetch data
      const service = new RedirectService(db)
      const [redirects, total] = await Promise.all([
        service.list(filter),
        service.count(filter)
      ])

      return c.json({
        data: redirects,
        pagination: {
          limit: filter.limit,
          offset: filter.offset,
          total
        }
      })
    } catch (error) {
      console.error('Error listing redirects:', error)
      return c.json(
        apiError(500, 'Failed to list redirects'),
        500
      )
    }
  })

  // GET /api/redirects/:id - Get redirect by ID
  api.get('/:id', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json(apiError(503, 'Database unavailable'), 503)
      }

      const id = c.req.param('id')
      const service = new RedirectService(db)
      const redirect = await service.getById(id)

      if (!redirect) {
        return c.json(
          apiError(404, `Redirect with ID ${id} not found`),
          404
        )
      }

      return c.json({ data: redirect })
    } catch (error) {
      console.error('Error getting redirect:', error)
      return c.json(
        apiError(500, 'Failed to get redirect'),
        500
      )
    }
  })

  // POST /api/redirects - Create new redirect
  api.post('/', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json(apiError(503, 'Database unavailable'), 503)
      }

      const body = await c.req.json<CreateRedirectInput>()

      // Basic validation
      if (!body.source || !body.destination) {
        return c.json(
          apiError(400, 'Source and destination are required'),
          400
        )
      }

      // Get user ID (from authenticated user or API context)
      const userId = c.get('user')?.id || 'api'

      const service = new RedirectService(db)
      const result = await service.create(body, userId)

      if (!result.success) {
        return c.json(
          apiError(400, result.error!),
          400
        )
      }

      return c.json({ data: result.redirect }, 201)
    } catch (error) {
      console.error('Error creating redirect:', error)
      return c.json(
        apiError(500, 'Failed to create redirect'),
        500
      )
    }
  })

  // PUT /api/redirects/:id - Update redirect
  api.put('/:id', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json(apiError(503, 'Database unavailable'), 503)
      }

      const id = c.req.param('id')
      const body = await c.req.json<UpdateRedirectInput>()

      const service = new RedirectService(db)
      const result = await service.update(id, body)

      if (!result.success) {
        const status = result.error === 'Redirect not found' ? 404 : 400
        return c.json(
          apiError(status, result.error!),
          status
        )
      }

      return c.json({ data: result.redirect })
    } catch (error) {
      console.error('Error updating redirect:', error)
      return c.json(
        apiError(500, 'Failed to update redirect'),
        500
      )
    }
  })

  // DELETE /api/redirects/:id - Delete redirect
  api.delete('/:id', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json(apiError(503, 'Database unavailable'), 503)
      }

      const id = c.req.param('id')

      const service = new RedirectService(db)
      const result = await service.delete(id)

      if (!result.success) {
        const status = result.error === 'Redirect not found' ? 404 : 400
        return c.json(
          apiError(status, result.error!),
          status
        )
      }

      return c.json({ success: true }, 200)
    } catch (error) {
      console.error('Error deleting redirect:', error)
      return c.json(
        apiError(500, 'Failed to delete redirect'),
        500
      )
    }
  })

  return api
}

export default createRedirectApiRoutes
```

### Mounting API Routes in Plugin
```typescript
// Source: Existing plugin index.ts pattern
import { Hono } from 'hono'
import { createRedirectApiRoutes } from './routes/api'
import { createRedirectAdminRoutes } from './routes/admin'

export function registerRedirectManagementPlugin(app: Hono) {
  // Mount API routes
  const apiRoutes = createRedirectApiRoutes()
  app.route('/api/redirects', apiRoutes)

  // Mount admin routes (existing)
  const adminRoutes = createRedirectAdminRoutes()
  app.route('/admin/redirects', adminRoutes)

  return app
}
```

### Example API Calls from Another Plugin
```typescript
// Source: REST API conventions + Hono client patterns
// Example: QR code plugin creating a redirect

// Internal call (has user context, no Bearer token needed)
async function createRedirectForQRCode(
  shortPath: string,
  targetUrl: string,
  c: any // Hono context
) {
  const response = await fetch(`${c.req.url.origin}/api/redirects`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      source: shortPath,
      destination: targetUrl,
      statusCode: 302,
      matchType: 0, // EXACT
      isActive: true
    })
  })

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.detail || 'Failed to create redirect')
  }

  const result = await response.json()
  return result.data
}

// External call (requires Bearer token)
async function createRedirectExternal(apiKey: string) {
  const response = await fetch('https://yoursite.com/api/redirects', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      source: '/promo',
      destination: 'https://example.com/promo-page',
      statusCode: 301
    })
  })

  return await response.json()
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Custom error formats | RFC 9457 Problem Details | RFC published 2023 (updated from RFC 7807) | Standardized error responses improve API interoperability |
| URI versioning required | Version only when needed | Ongoing best practice | Simpler initial API, version when breaking changes occur |
| Separate auth per route | Middleware-based auth | Hono pattern since inception | Cleaner code, DRY principle, centralized security |
| Express.js for APIs | Hono for edge runtime | Hono released 2022, mature 2024+ | Better performance on Cloudflare Workers, smaller bundle |

**Deprecated/outdated:**
- Custom JSON error formats: RFC 9457 provides standardization
- Rails-like controllers: Hono best practices recommend direct handlers for type inference
- Always versioning APIs: Modern practice is to version only when introducing breaking changes

## Open Questions

Things that couldn't be fully resolved:

1. **API Key Storage Strategy**
   - What we know: Bearer auth middleware can validate tokens from environment variables or database
   - What's unclear: Whether SonicJS has an established API key management system (api_keys table, plugin settings, env vars)
   - Recommendation: Start with environment variable (REDIRECTS_API_KEY), document in README, consider database-backed keys in future phase

2. **Internal Plugin Authentication Pattern**
   - What we know: Plugins share the same Hono context and can access c.get('user')
   - What's unclear: Official SonicJS pattern for plugin-to-plugin API calls (should they use fetch, direct service calls, or shared context?)
   - Recommendation: Support both - allow direct service imports for internal use, expose API for external/decoupled access. Check for user context to bypass Bearer auth.

3. **Rate Limiting Requirements**
   - What we know: Cloudflare Workers has built-in rate limiting features
   - What's unclear: Whether API endpoints need rate limiting for this phase or if it's deferred
   - Recommendation: Document rate limiting as future enhancement, not required for phase 5 (no requirement listed)

## Sources

### Primary (HIGH confidence)
- [Hono Best Practices](https://hono.dev/docs/guides/best-practices) - Routing patterns, avoiding controllers
- [Hono Routing API](https://hono.dev/docs/api/routing) - HTTP methods, route parameters, app.route()
- [Hono Bearer Auth Middleware](https://hono.dev/docs/middleware/builtin/bearer-auth) - Authentication configuration
- Existing codebase:
  - `src/plugins/redirect-management/services/redirect.ts` - Complete service implementation
  - `src/plugins/redirect-management/routes/admin.ts` - Route patterns, DB context handling
  - `src/plugins/redirect-management/types.ts` - Type definitions
  - `package.json` - Hono ^4.11.7, Zod ^3.25.67

### Secondary (MEDIUM confidence)
- [REST API Error Handling - Baeldung](https://www.baeldung.com/rest-api-error-handling-best-practices) - RFC 9457 Problem Details
- [REST API URI Naming Conventions](https://restfulapi.net/resource-naming/) - RESTful endpoint patterns
- [REST API Naming - Moesif](https://www.moesif.com/blog/technical/api-development/The-Ultimate-Guide-to-REST-API-Naming-Convention/) - CRUD endpoints, plural nouns
- [API Versioning Best Practices - xMatters](https://www.xmatters.com/blog/api-versioning-strategies) - When to version, strategies

### Tertiary (LOW confidence)
- Various DEV.to articles on Hono + REST APIs - Patterns align with official docs but not authoritative

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Verified from package.json and official Hono docs
- Architecture: HIGH - Patterns from official Hono docs and existing codebase
- Pitfalls: HIGH - Based on common REST API mistakes and Hono-specific issues from docs/discussions
- API key management: MEDIUM - SonicJS-specific patterns not fully documented, general approaches researched

**Research date:** 2026-01-30
**Valid until:** 2026-03-01 (30 days - REST API patterns stable, Hono stable)
