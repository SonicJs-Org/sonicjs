# Routing and Middleware Documentation

## Table of Contents
1. [Overview](#overview)
2. [Middleware Pipeline](#middleware-pipeline)
3. [Authentication Middleware](#authentication-middleware)
4. [Authorization and Permissions Middleware](#authorization-and-permissions-middleware)
5. [Bootstrap Middleware](#bootstrap-middleware)
6. [Logging Middleware](#logging-middleware)
7. [Performance Middleware](#performance-middleware)
8. [Plugin Middleware](#plugin-middleware)
9. [Route Structure](#route-structure)
10. [Creating Custom Middleware](#creating-custom-middleware)
11. [Complete Examples](#complete-examples)

## Overview

SonicJS AI uses [Hono](https://hono.dev/), a lightweight web framework optimized for Cloudflare Workers. The middleware pipeline processes every request through a series of layers before reaching route handlers.

### Key Concepts

- **Middleware**: Functions that execute before route handlers to process requests
- **Middleware Ordering**: Order matters - middleware executes in the sequence it's registered
- **Route Protection**: Middleware can protect routes based on authentication, roles, and permissions
- **Context Object**: Middleware can set values on the context (`c.set()`) for downstream use

## Middleware Pipeline

The middleware pipeline executes in the following order for every request:

```typescript
// File: /Users/lane/Dev/refs/sonicjs-ai/src/index.ts

// 1. Bootstrap - System initialization (runs once per worker)
app.use('*', bootstrapMiddleware())

// 2. Logging - Request/response logging
app.use('*', loggingMiddleware())
app.use('*', securityLoggingMiddleware())
app.use('*', performanceLoggingMiddleware(1000)) // Log slow requests

// 3. Standard Middleware
app.use('*', logger())              // Hono's built-in logger
app.use('*', cors())                // CORS headers
app.use('*', securityHeaders())     // Security headers
app.use('/api/*', prettyJSON())     // JSON formatting for API routes

// 4. Route-specific middleware (applied to specific paths)
app.use('/admin/*', requireAuth())
app.use('/admin/*', requireRole(['admin', 'editor']))
app.use('/admin/*', cacheHeaders(60))
```

### Middleware Execution Order

```
Request
  ↓
Bootstrap Middleware → Check/run system initialization
  ↓
Logging Middleware → Log request start
  ↓
Security Logging → Check for suspicious patterns
  ↓
Performance Logging → Track request timing
  ↓
Standard Middleware → CORS, security headers, etc.
  ↓
Route-specific Middleware → Auth, roles, permissions
  ↓
Route Handler → Execute business logic
  ↓
Logging Middleware → Log request completion
  ↓
Response
```

## Authentication Middleware

The authentication system uses **Better Auth** for sign-in, sign-up, and sessions. Sessions are stored in an HTTP-only cookie (`better-auth.session_token`). A global middleware populates `c.set('user', { userId, email, role })` from the session.

### File Location
`packages/core/src/middleware/auth.ts`

### AuthManager (legacy / seed-admin only)

```typescript
import { AuthManager } from '../middleware/auth'

// Hash password (used only for legacy flows, e.g. seed-admin)
const hash = await AuthManager.hashPassword(password)

// Verify password
const isValid = await AuthManager.verifyPassword(password, hash)
```

Sign-in and sign-up use Better Auth; do not use `AuthManager.generateToken` or `AuthManager.verifyToken` for new features.

### requireAuth Middleware

Requires valid authentication to access a route.

```typescript
import { requireAuth } from '../middleware/auth'

// Protect a route
app.get('/protected', requireAuth(), async (c) => {
  const user = c.get('user')
  // user contains: { userId, email, role } from Better Auth session

  return c.json({ message: 'Welcome!', user })
})
```

**How it works:**

1. Global session middleware calls Better Auth `getSession` and sets `user` on context when a valid session cookie is present.
2. `requireAuth()` checks for `c.get('user')`; if missing, returns 401 or redirects to login.
3. No separate Bearer token or KV cache; authentication is session-cookie based.

**Example Usage:**

```typescript
// API route with authentication
authRoutes.get('/me', requireAuth(), async (c) => {
  const user = c.get('user')
  const db = c.env.DB

  const userData = await db.prepare(
    'SELECT id, email, username, role FROM users WHERE id = ?'
  ).bind(user.userId).first()

  return c.json({ user: userData })
})
```

### requireRole Middleware

Requires specific role(s) to access a route.

```typescript
import { requireRole } from '../middleware/auth'

// Single role
app.get('/admin-only',
  requireAuth(),
  requireRole('admin'),
  async (c) => {
    return c.json({ message: 'Admin area' })
  }
)

// Multiple roles (any of them)
app.get('/content-edit',
  requireAuth(),
  requireRole(['admin', 'editor']),
  async (c) => {
    return c.json({ message: 'Content editing area' })
  }
)
```

**Role Hierarchy:**
- `admin` - Full system access
- `editor` - Content management and publishing
- `viewer` - Read-only access

### optionalAuth Middleware

Allows authenticated and unauthenticated access, but populates user if authenticated.

```typescript
import { optionalAuth } from '../middleware/auth'

// Public API with optional auth
app.get('/content', optionalAuth(), async (c) => {
  const user = c.get('user')
  const db = c.env.DB

  // Show different content based on authentication
  const query = user
    ? 'SELECT * FROM content WHERE status IN (?, ?, ?)'
    : 'SELECT * FROM content WHERE status = ?'

  const params = user
    ? ['published', 'draft', 'scheduled']
    : ['published']

  const { results } = await db.prepare(query).bind(...params).all()

  return c.json({ data: results, authenticated: !!user })
})
```

## Authorization and Permissions Middleware

Fine-grained permission system for controlling access to specific resources.

### File Location
`/Users/lane/Dev/refs/sonicjs-ai/src/middleware/permissions.ts`

### Permission Manager

```typescript
import { PermissionManager } from '../middleware/permissions'

// Get user permissions
const permissions = await PermissionManager.getUserPermissions(db, userId)
// Returns: { userId, role, permissions: string[], teamPermissions: {} }

// Check single permission
const hasPermission = await PermissionManager.hasPermission(
  db,
  userId,
  'content.edit'
)

// Check multiple permissions
const permissionMap = await PermissionManager.checkMultiplePermissions(
  db,
  userId,
  ['content.edit', 'content.publish', 'users.create']
)
// Returns: { 'content.edit': true, 'content.publish': false, ... }

// Clear user permission cache
PermissionManager.clearUserCache(userId)

// Clear all permission cache
PermissionManager.clearAllCache()
```

### requirePermission Middleware

Requires specific permission to access a route.

```typescript
import { requirePermission } from '../middleware/permissions'

// Single permission
app.post('/content',
  requireAuth(),
  requirePermission('content.create'),
  async (c) => {
    // User has content.create permission
    return c.json({ message: 'Content created' })
  }
)

// Permission with team context
app.get('/teams/:teamId/settings',
  requireAuth(),
  requirePermission('team.settings', 'teamId'),
  async (c) => {
    const teamId = c.req.param('teamId')
    // User has team.settings permission for this specific team
    return c.json({ message: `Team ${teamId} settings` })
  }
)
```

### requireAnyPermission Middleware

Requires at least one of the specified permissions.

```typescript
import { requireAnyPermission } from '../middleware/permissions'

app.post('/content/publish',
  requireAuth(),
  requireAnyPermission([
    'content.publish',
    'content.admin'
  ]),
  async (c) => {
    // User has either content.publish OR content.admin permission
    return c.json({ message: 'Content published' })
  }
)
```

### Permission Naming Convention

Permissions follow the pattern: `resource.action`

**Common Permissions:**
- `content.create` - Create content
- `content.edit` - Edit content
- `content.publish` - Publish content
- `content.delete` - Delete content
- `users.create` - Create users
- `users.edit` - Edit users
- `users.delete` - Delete users
- `team.settings` - Manage team settings
- `media.upload` - Upload media files
- `media.delete` - Delete media files

### Activity Logging

Log user activities for audit trails:

```typescript
import { logActivity } from '../middleware/permissions'

await logActivity(
  db,
  userId,
  'content.published',           // action
  'content',                      // resourceType
  contentId,                      // resourceId
  { title: 'My Post' },          // details (optional)
  ipAddress,                      // IP address (optional)
  userAgent                       // User agent (optional)
)
```

## Bootstrap Middleware

Handles system initialization on worker startup.

### File Location
`/Users/lane/Dev/refs/sonicjs-ai/src/middleware/bootstrap.ts`

### Purpose

The bootstrap middleware runs once per Cloudflare Worker instance to:
1. Run pending database migrations
2. Sync collection configurations
3. Bootstrap core plugins
4. Install demo plugins (development only)

### Implementation

```typescript
import { bootstrapMiddleware, resetBootstrap } from '../middleware/bootstrap'

// Apply to all routes
app.use('*', bootstrapMiddleware())

// Reset bootstrap flag (useful for testing)
resetBootstrap()
```

### How It Works

```typescript
let bootstrapComplete = false

export function bootstrapMiddleware() {
  return async (c: Context, next: Next) => {
    // Skip if already bootstrapped
    if (bootstrapComplete) {
      return next()
    }

    // Skip bootstrap for static assets
    const path = c.req.path
    if (
      path.startsWith('/images/') ||
      path.startsWith('/assets/') ||
      path === '/health' ||
      path.endsWith('.js') ||
      path.endsWith('.css')
    ) {
      return next()
    }

    try {
      console.log('[Bootstrap] Starting system initialization...')

      // 1. Run database migrations
      const migrationService = new MigrationService(c.env.DB)
      await migrationService.runPendingMigrations()

      // 2. Sync collection configurations
      await syncCollections(c.env.DB)

      // 3. Bootstrap core plugins
      const bootstrapService = new PluginBootstrapService(c.env.DB)
      const needsBootstrap = await bootstrapService.isBootstrapNeeded()

      if (needsBootstrap) {
        await bootstrapService.bootstrapCorePlugins()
        await bootstrapService.installDemoPlugins()
      }

      bootstrapComplete = true
      console.log('[Bootstrap] System initialization completed')

    } catch (error) {
      console.error('[Bootstrap] Error during initialization:', error)
      // Continue even if bootstrap fails
    }

    return next()
  }
}
```

### Best Practices

1. Bootstrap runs on first request only
2. Skips static assets for performance
3. Continues even if bootstrap fails (graceful degradation)
4. Use `resetBootstrap()` in tests to force re-initialization

## Logging Middleware

Comprehensive request/response logging with security monitoring.

### File Location
`/Users/lane/Dev/refs/sonicjs-ai/src/middleware/logging.ts`

### Standard Logging Middleware

Logs all HTTP requests and responses.

```typescript
import { loggingMiddleware } from '../middleware/logging'

app.use('*', loggingMiddleware())
```

**What it logs:**

- Request method, URL, and headers
- Response status code
- Request duration
- User ID (if authenticated)
- IP address and user agent
- Request ID (generated UUID)

**Example logged data:**

```typescript
{
  method: 'POST',
  url: 'https://example.com/api/content',
  status: 201,
  duration: 145, // milliseconds
  userId: 'user-123',
  requestId: 'req-abc-xyz',
  ipAddress: '192.168.1.1',
  userAgent: 'Mozilla/5.0...',
  source: 'http-middleware'
}
```

### Detailed Logging Middleware

Provides more verbose logging including headers and request body.

```typescript
import { detailedLoggingMiddleware } from '../middleware/logging'

// Use for specific routes that need detailed logging
app.use('/api/critical/*', detailedLoggingMiddleware())
```

**Additional information logged:**

- Request headers (all)
- Response headers (all)
- Content-Type and Content-Length
- Response size

### Security Logging Middleware

Monitors suspicious activity and security events.

```typescript
import { securityLoggingMiddleware } from '../middleware/logging'

app.use('*', securityLoggingMiddleware())
```

**What it monitors:**

- Suspicious request patterns (SQL injection, XSS attempts)
- Authentication failures
- Admin area access
- Unauthorized access attempts

**Suspicious patterns detected:**

```typescript
const suspiciousPatterns = [
  /script[^>]*>/i,        // XSS attempts
  /javascript:/i,         // JavaScript protocol
  /on\w+\s*=/i,          // Event handlers
  /\.\.\/\.\.\//,        // Directory traversal
  /\/etc\/passwd/i,      // System file access
  /union\s+select/i,     // SQL injection
  /drop\s+table/i        // SQL injection
]
```

**Example security log:**

```typescript
await logger.logSecurity(
  'Suspicious request pattern detected',
  'medium', // severity: low, medium, high, critical
  {
    userId: user?.userId,
    requestId,
    ipAddress,
    userAgent,
    method,
    url,
    tags: ['suspicious-pattern', 'xss-attempt']
  }
)
```

### Performance Logging Middleware

Tracks slow requests for performance monitoring.

```typescript
import { performanceLoggingMiddleware } from '../middleware/logging'

// Log requests slower than 1000ms (1 second)
app.use('*', performanceLoggingMiddleware(1000))

// Log requests slower than 500ms for critical API
app.use('/api/critical/*', performanceLoggingMiddleware(500))
```

**Example performance log:**

```typescript
{
  message: 'Slow request detected: GET /api/content took 1234ms',
  method: 'GET',
  url: '/api/content',
  duration: 1234,
  threshold: 1000,
  userId: 'user-123',
  requestId: 'req-abc-xyz',
  tags: ['slow-request', 'performance']
}
```

## Performance Middleware

Middleware for caching, compression, and security headers.

### File Location
`/Users/lane/Dev/refs/sonicjs-ai/src/middleware/performance.ts`

### Cache Headers Middleware

Adds cache-control headers to responses.

```typescript
import { cacheHeaders } from '../middleware/performance'

// Cache for 60 seconds
app.use('/admin/*', cacheHeaders(60))

// Cache for 5 minutes
app.use('/api/static/*', cacheHeaders(300))
```

**How it works:**

- Only caches successful HTML responses (200 status)
- Sets `Cache-Control: private, max-age={maxAge}`
- Private caching prevents CDN caching of authenticated pages

### Compression Middleware

Compresses responses with gzip or brotli.

```typescript
import { compressionMiddleware } from '../middleware/performance'

app.use('*', compressionMiddleware)
```

**Note:** Currently disabled in production due to encoding issues with Cloudflare Workers.

### Security Headers Middleware

Adds security headers to all responses.

```typescript
import { securityHeaders } from '../middleware/performance'

app.use('*', securityHeaders())
```

**Headers added:**

```typescript
'X-Content-Type-Options': 'nosniff'
'X-Frame-Options': 'SAMEORIGIN'
'X-XSS-Protection': '1; mode=block'
```

## Plugin Middleware

Controls access to plugin routes based on plugin activation status.

### File Location
`/Users/lane/Dev/refs/sonicjs-ai/src/middleware/plugin-middleware.ts`

### requireActivePlugin Middleware

Ensures a plugin is active before allowing access to its routes.

```typescript
import { requireActivePlugin } from '../middleware/plugin-middleware'

// Protect FAQ plugin routes
app.use('/admin/faq/*', requireActivePlugin('faq'))
app.route('/admin/faq', adminFAQRoutes)

// Protect workflow plugin routes
app.use('/admin/workflow/*', requireActivePlugin('workflow'))
app.route('/admin/workflow', createWorkflowAdminRoutes())

// Protect cache plugin routes
app.use('/admin/cache/*', requireActivePlugin('cache'))
app.route('/admin/cache', cacheRoutes)
```

**How it works:**

1. Queries database for plugin status
2. Returns 404 with user-friendly message if plugin is not active
3. Allows request to continue if plugin is active
4. Fails open (allows access) if database query fails

**Example error page:**

```html
<div class="min-h-screen flex items-center justify-center bg-gray-900">
  <div class="text-center">
    <h1 class="text-4xl font-bold text-white mb-4">
      Feature Not Available
    </h1>
    <p class="text-gray-300 mb-6">
      The faq plugin is not currently active.
    </p>
    <a href="/admin" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg">
      Return to Admin Dashboard
    </a>
  </div>
</div>
```

### requireActivePlugins Middleware

Requires multiple plugins to be active.

```typescript
import { requireActivePlugins } from '../middleware/plugin-middleware'

// Requires both workflow AND email plugins
app.use('/admin/notifications/*', requireActivePlugins([
  'workflow',
  'email'
]))
```

### Helper Functions

```typescript
import {
  getActivePlugins,
  isPluginActive
} from '../middleware/plugin-middleware'

// Get all active plugins
const plugins = await getActivePlugins(db)
// Returns: [{ name, display_name, icon, settings }, ...]

// Check if specific plugin is active
const isActive = await isPluginActive(db, 'faq')
// Returns: boolean
```

## Route Structure

SonicJS AI organizes routes into logical modules.

### Route File Organization

```
src/routes/
├── api.ts              # Public API endpoints
├── api-media.ts        # Media API endpoints
├── admin.ts            # Admin dashboard and core routes
├── admin-content.ts    # Content management routes
├── admin-faq.ts        # FAQ management routes
├── admin-design.ts     # Design/theme management
├── admin-checkboxes.ts # Checkbox field type routes
├── admin-logs.ts       # System logs viewer
├── admin-users.ts      # User management routes
├── admin-media.ts      # Media library management
├── admin-plugins.ts    # Plugin management routes
├── auth.ts             # Authentication routes
├── content.ts          # Content API routes
├── docs.ts             # Documentation routes
└── media.ts            # Media serving routes
```

### Public Routes

No authentication required.

```typescript
// Authentication pages
GET  /auth/login                    # Login page
POST /auth/login                    # Login form submission
GET  /auth/register                 # Registration page
POST /auth/register                 # Registration form submission
GET  /auth/logout                   # Logout
POST /auth/logout                   # Logout API

// Password reset
POST /auth/request-password-reset   # Request password reset
GET  /auth/reset-password           # Reset password page
POST /auth/reset-password           # Reset password form

// Invitation acceptance
GET  /auth/accept-invitation        # Accept invitation page
POST /auth/accept-invitation        # Accept invitation form

// Public API
GET  /api/                          # OpenAPI specification
GET  /api/health                    # Health check
GET  /api/collections               # List collections
GET  /api/content                   # List content (published only)
GET  /api/collections/:collection/content  # Collection content

// Documentation
GET  /docs                          # Documentation home

// Static files
GET  /images/*                      # Serve images
GET  /media/serve/:key              # Serve media files

// Health check
GET  /health                        # System health
```

### Authenticated API Routes

Requires authentication (Bearer token or cookie).

```typescript
// User info
GET  /auth/me                       # Get current user
POST /auth/refresh                  # Refresh token

// Media upload
POST /api/media/upload              # Upload single file
POST /api/media/upload-multiple     # Upload multiple files
POST /api/media/bulk-delete         # Delete multiple files
DELETE /api/media/:id               # Delete single file
PATCH /api/media/:id                # Update file metadata
```

### Admin Routes

Requires authentication + admin or editor role.

```typescript
// Dashboard
GET  /admin/                        # Admin dashboard
GET  /admin/api/stats               # Dashboard statistics (HTMX)
GET  /admin/api/system-status       # System status (HTMX)

// Collections
GET  /admin/collections             # List collections
GET  /admin/collections/new         # New collection form
POST /admin/collections             # Create collection
GET  /admin/collections/:id         # Edit collection
PUT  /admin/collections/:id         # Update collection
DELETE /admin/collections/:id       # Delete collection

// Collection fields
POST /admin/collections/:id/fields  # Add field
PUT  /admin/collections/:collectionId/fields/:fieldId  # Update field
DELETE /admin/collections/:collectionId/fields/:fieldId  # Delete field
POST /admin/collections/:collectionId/fields/reorder  # Reorder fields

// Content
GET  /admin/content/                # List content
GET  /admin/content/new             # New content form
POST /admin/content/                # Create content
GET  /admin/content/:id/edit        # Edit content form
PUT  /admin/content/:id             # Update content
DELETE /admin/content/:id           # Delete content

// Media
GET  /admin/media/                  # Media library
GET  /admin/media/search            # Search media (HTMX)
GET  /admin/media/:id/details       # File details (HTMX)
POST /admin/media/upload            # Upload files
PUT  /admin/media/:id               # Update metadata
DELETE /admin/media/:id             # Delete file

// Users
GET  /admin/users                   # List users
POST /admin/users/:id/toggle        # Toggle user status
GET  /admin/users/export            # Export users CSV

// Plugins
GET  /admin/plugins                 # List plugins
POST /admin/plugins/:id/toggle      # Toggle plugin status
GET  /admin/plugins/:id             # Plugin details

// Settings
GET  /admin/settings                # Settings page
GET  /admin/settings/:tab           # Settings tab
POST /admin/settings                # Save settings

// Migrations
GET  /admin/api/migrations/status   # Migration status
POST /admin/api/migrations/run      # Run migrations
GET  /admin/api/migrations/validate # Validate schema

// Logs
GET  /admin/logs                    # View logs
GET  /admin/logs/:id                # Log details

// API Reference
GET  /admin/api-reference           # API documentation
GET  /admin/field-types             # Field types reference
```

### Plugin Routes

Routes that require specific plugins to be active.

```typescript
// FAQ Plugin
GET  /admin/faq/                    # List FAQs
GET  /admin/faq/new                 # New FAQ form
POST /admin/faq/                    # Create FAQ
GET  /admin/faq/:id                 # Edit FAQ
PUT  /admin/faq/:id                 # Update FAQ
DELETE /admin/faq/:id               # Delete FAQ

// Workflow Plugin
GET  /admin/workflow/               # Workflow dashboard
GET  /admin/workflow/rules          # Workflow rules
POST /admin/workflow/rules          # Create rule
GET  /api/workflow/content/:id      # Content workflow status
POST /api/workflow/content/:id/transition  # Transition content

// Cache Plugin
GET  /admin/cache/                  # Cache dashboard
POST /admin/cache/clear             # Clear cache
GET  /admin/cache/stats             # Cache statistics
```

## Creating Custom Middleware

### Basic Middleware Structure

```typescript
import { Context, Next } from 'hono'

type Bindings = {
  DB: D1Database
  KV: KVNamespace
}

type Variables = {
  user?: {
    userId: string
    email: string
    role: string
  }
  customData?: any
}

export function customMiddleware() {
  return async (c: Context<{ Bindings: Bindings; Variables: Variables }>, next: Next) => {
    // 1. Pre-processing (before route handler)
    console.log('Before route handler')

    // 2. Set context variables
    c.set('customData', { foo: 'bar' })

    // 3. Call next middleware/handler
    await next()

    // 4. Post-processing (after route handler)
    console.log('After route handler')
  }
}
```

### Example: Request Timing Middleware

```typescript
export function timingMiddleware() {
  return async (c: Context, next: Next) => {
    const start = Date.now()

    // Store start time in context
    c.set('startTime', start)

    // Execute request
    await next()

    // Calculate duration
    const duration = Date.now() - start

    // Add header to response
    c.header('X-Response-Time', `${duration}ms`)

    // Log if slow
    if (duration > 1000) {
      console.warn(`Slow request: ${c.req.method} ${c.req.path} - ${duration}ms`)
    }
  }
}

// Usage
app.use('*', timingMiddleware())
```

### Example: Rate Limiting Middleware

```typescript
export function rateLimitMiddleware(maxRequests: number, windowMs: number) {
  const requests = new Map<string, { count: number; resetTime: number }>()

  return async (c: Context, next: Next) => {
    const clientId = c.req.header('cf-connecting-ip') || 'unknown'
    const now = Date.now()

    // Get or create rate limit record
    let record = requests.get(clientId)

    if (!record || now > record.resetTime) {
      record = { count: 0, resetTime: now + windowMs }
      requests.set(clientId, record)
    }

    // Check rate limit
    if (record.count >= maxRequests) {
      const retryAfter = Math.ceil((record.resetTime - now) / 1000)
      c.header('Retry-After', retryAfter.toString())
      return c.json({ error: 'Rate limit exceeded' }, 429)
    }

    // Increment counter
    record.count++

    // Add rate limit headers
    c.header('X-RateLimit-Limit', maxRequests.toString())
    c.header('X-RateLimit-Remaining', (maxRequests - record.count).toString())
    c.header('X-RateLimit-Reset', record.resetTime.toString())

    await next()
  }
}

// Usage
app.use('/api/*', rateLimitMiddleware(100, 60000)) // 100 requests per minute
```

### Example: Request Validation Middleware

```typescript
import { z } from 'zod'

export function validateQuery(schema: z.ZodSchema) {
  return async (c: Context, next: Next) => {
    const query = Object.fromEntries(
      new URL(c.req.url).searchParams.entries()
    )

    const result = schema.safeParse(query)

    if (!result.success) {
      return c.json({
        error: 'Invalid query parameters',
        details: result.error.errors
      }, 400)
    }

    // Store validated query in context
    c.set('validatedQuery', result.data)

    await next()
  }
}

// Usage
const paginationSchema = z.object({
  page: z.string().regex(/^\d+$/).transform(Number).default('1'),
  limit: z.string().regex(/^\d+$/).transform(Number).default('20'),
  sort: z.enum(['asc', 'desc']).default('desc')
})

app.get('/content',
  validateQuery(paginationSchema),
  async (c) => {
    const query = c.get('validatedQuery')
    // query is typed and validated
    return c.json({ page: query.page, limit: query.limit })
  }
)
```

### Example: Database Transaction Middleware

```typescript
export function withTransaction() {
  return async (c: Context, next: Next) => {
    const db = c.env.DB

    try {
      // Start transaction
      await db.exec('BEGIN TRANSACTION')

      // Store transaction flag
      c.set('inTransaction', true)

      // Execute route handler
      await next()

      // Commit if successful
      await db.exec('COMMIT')
    } catch (error) {
      // Rollback on error
      await db.exec('ROLLBACK')
      throw error
    }
  }
}

// Usage
app.post('/bulk-operation',
  requireAuth(),
  withTransaction(),
  async (c) => {
    // All database operations will be in a transaction
    const db = c.env.DB

    await db.prepare('INSERT INTO table1 ...').run()
    await db.prepare('INSERT INTO table2 ...').run()

    return c.json({ message: 'All changes committed' })
  }
)
```

## Complete Examples

### Example 1: Protected Admin Route with Logging

```typescript
import { Hono } from 'hono'
import { requireAuth, requireRole } from '../middleware/auth'
import { requirePermission } from '../middleware/permissions'
import { logActivity } from '../middleware/permissions'

const app = new Hono()

// Admin route with authentication, role, and permission checks
app.post('/admin/users/:id/delete',
  requireAuth(),                       // Require authentication
  requireRole(['admin']),              // Require admin role
  requirePermission('users.delete'),   // Require specific permission
  async (c) => {
    const userId = c.req.param('id')
    const currentUser = c.get('user')
    const db = c.env.DB

    try {
      // Soft delete user
      await db.prepare(
        'UPDATE users SET is_active = 0, deleted_at = ? WHERE id = ?'
      ).bind(Date.now(), userId).run()

      // Log activity
      await logActivity(
        db,
        currentUser.userId,
        'user.deleted',
        'users',
        userId,
        { deletedUserId: userId },
        c.req.header('cf-connecting-ip'),
        c.req.header('user-agent')
      )

      return c.json({
        message: 'User deleted successfully',
        userId
      })
    } catch (error) {
      console.error('Error deleting user:', error)
      return c.json({ error: 'Failed to delete user' }, 500)
    }
  }
)
```

### Example 2: Public API with Optional Authentication

```typescript
import { Hono } from 'hono'
import { optionalAuth } from '../middleware/auth'
import { getCacheService, CACHE_CONFIGS } from '../plugins/cache'

const app = new Hono()

app.get('/api/content',
  optionalAuth(),  // Optional authentication
  async (c) => {
    const user = c.get('user')
    const db = c.env.DB
    const limit = Math.min(
      parseInt(c.req.query('limit') || '50'),
      100
    )

    // Use cache
    const cache = getCacheService(CACHE_CONFIGS.api!)
    const cacheKey = cache.generateKey(
      'content-list',
      `user:${user?.userId || 'public'}:limit:${limit}`
    )

    const cached = await cache.get(cacheKey)
    if (cached) {
      c.header('X-Cache-Status', 'HIT')
      return c.json(cached)
    }

    // Build query based on authentication
    let query = 'SELECT * FROM content WHERE '
    const params: any[] = []

    if (user) {
      // Authenticated users see draft, published, and scheduled
      query += 'status IN (?, ?, ?)'
      params.push('draft', 'published', 'scheduled')
    } else {
      // Unauthenticated users only see published
      query += 'status = ?'
      params.push('published')
    }

    query += ` ORDER BY created_at DESC LIMIT ${limit}`

    const { results } = await db.prepare(query)
      .bind(...params)
      .all()

    const response = {
      data: results,
      meta: {
        count: results.length,
        limit,
        authenticated: !!user,
        timestamp: new Date().toISOString()
      }
    }

    // Cache the response
    await cache.set(cacheKey, response)
    c.header('X-Cache-Status', 'MISS')

    return c.json(response)
  }
)
```

### Example 3: Multi-step Workflow with Middleware Chain

```typescript
import { Hono } from 'hono'
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod'
import { requireAuth } from '../middleware/auth'
import { requirePermission } from '../middleware/permissions'
import { logActivity } from '../middleware/permissions'

const app = new Hono()

// Validation schema
const publishSchema = z.object({
  contentId: z.string().uuid(),
  publishAt: z.number().optional(),
  notifySubscribers: z.boolean().default(false)
})

// Custom middleware to check content ownership
function requireContentOwnership() {
  return async (c: Context, next: Next) => {
    const { contentId } = await c.req.json()
    const user = c.get('user')
    const db = c.env.DB

    const content = await db.prepare(
      'SELECT author_id FROM content WHERE id = ?'
    ).bind(contentId).first() as any

    if (!content) {
      return c.json({ error: 'Content not found' }, 404)
    }

    // Allow if user is author or has admin role
    if (content.author_id !== user.userId && user.role !== 'admin') {
      return c.json({ error: 'Not authorized' }, 403)
    }

    // Store content in context
    c.set('content', content)

    await next()
  }
}

// Middleware chain for publishing content
app.post('/content/publish',
  requireAuth(),                          // 1. Require authentication
  requirePermission('content.publish'),   // 2. Require permission
  zValidator('json', publishSchema),      // 3. Validate request body
  requireContentOwnership(),              // 4. Check ownership
  async (c) => {                          // 5. Route handler
    const user = c.get('user')
    const data = c.req.valid('json')
    const content = c.get('content')
    const db = c.env.DB

    const publishAt = data.publishAt || Date.now()
    const status = publishAt > Date.now() ? 'scheduled' : 'published'

    // Update content
    await db.prepare(`
      UPDATE content
      SET status = ?, published_at = ?, scheduled_at = ?, updated_at = ?
      WHERE id = ?
    `).bind(
      status,
      status === 'published' ? publishAt : null,
      status === 'scheduled' ? publishAt : null,
      Date.now(),
      data.contentId
    ).run()

    // Send notifications
    if (data.notifySubscribers) {
      // Queue notification job
      await c.env.EMAIL_QUEUE?.send({
        type: 'content_published',
        contentId: data.contentId,
        userId: user.userId
      })
    }

    // Log activity
    await logActivity(
      db,
      user.userId,
      status === 'published' ? 'content.published' : 'content.scheduled',
      'content',
      data.contentId,
      {
        status,
        publishAt,
        notifySubscribers: data.notifySubscribers
      },
      c.req.header('cf-connecting-ip'),
      c.req.header('user-agent')
    )

    return c.json({
      message: `Content ${status} successfully`,
      contentId: data.contentId,
      status,
      publishAt: new Date(publishAt).toISOString()
    })
  }
)
```

### Example 4: Plugin Route with Activation Check

```typescript
import { Hono } from 'hono'
import { requireAuth, requireRole } from '../middleware/auth'
import { requireActivePlugin } from '../middleware/plugin-middleware'

const app = new Hono()

// All routes in this router require 'workflow' plugin to be active
app.use('*', requireActivePlugin('workflow'))
app.use('*', requireAuth())
app.use('*', requireRole(['admin', 'editor']))

app.get('/admin/workflow/', async (c) => {
  const db = c.env.DB

  // Get workflow rules
  const { results: rules } = await db.prepare(`
    SELECT * FROM workflow_rules
    WHERE is_active = 1
    ORDER BY priority DESC
  `).all()

  // Get workflow history
  const { results: history } = await db.prepare(`
    SELECT * FROM workflow_history
    ORDER BY created_at DESC
    LIMIT 50
  `).all()

  return c.json({
    rules,
    history,
    meta: {
      rulesCount: rules.length,
      timestamp: new Date().toISOString()
    }
  })
})

app.post('/admin/workflow/rules', async (c) => {
  const user = c.get('user')
  const data = await c.req.json()
  const db = c.env.DB

  const ruleId = crypto.randomUUID()

  await db.prepare(`
    INSERT INTO workflow_rules (
      id, name, description, conditions, actions,
      priority, is_active, created_by, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    ruleId,
    data.name,
    data.description,
    JSON.stringify(data.conditions),
    JSON.stringify(data.actions),
    data.priority || 0,
    1,
    user.userId,
    Date.now()
  ).run()

  return c.json({
    message: 'Workflow rule created',
    ruleId
  }, 201)
})

export default app
```

### Example 5: HTMX-powered Admin Route

```typescript
import { Hono } from 'hono'
import { html } from 'hono/html'
import { requireAuth, requireRole } from '../middleware/auth'

const app = new Hono()

app.use('*', requireAuth())
app.use('*', requireRole(['admin', 'editor']))

// Render full page
app.get('/admin/content/', async (c) => {
  const db = c.env.DB
  const { results } = await db.prepare(`
    SELECT * FROM content
    ORDER BY created_at DESC
    LIMIT 20
  `).all()

  return c.html(html`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Content Management</title>
        <script src="https://unpkg.com/htmx.org@1.9.10"></script>
      </head>
      <body>
        <h1>Content</h1>

        <!-- Search form -->
        <form
          hx-get="/admin/content/search"
          hx-target="#content-list"
          hx-trigger="input changed delay:500ms from:#search-input"
        >
          <input
            id="search-input"
            name="q"
            type="text"
            placeholder="Search content..."
          />
        </form>

        <!-- Content list -->
        <div id="content-list">
          ${results.map((item: any) => html`
            <div class="content-item">
              <h2>${item.title}</h2>
              <p>${item.status}</p>
              <button
                hx-delete="/admin/content/${item.id}"
                hx-confirm="Delete this content?"
                hx-target="closest .content-item"
                hx-swap="outerHTML"
              >
                Delete
              </button>
            </div>
          `)}
        </div>
      </body>
    </html>
  `)
})

// HTMX endpoint for search
app.get('/admin/content/search', async (c) => {
  const query = c.req.query('q') || ''
  const db = c.env.DB

  const { results } = await db.prepare(`
    SELECT * FROM content
    WHERE title LIKE ? OR data LIKE ?
    ORDER BY created_at DESC
    LIMIT 20
  `).bind(`%${query}%`, `%${query}%`).all()

  return c.html(html`
    ${results.map((item: any) => html`
      <div class="content-item">
        <h2>${item.title}</h2>
        <p>${item.status}</p>
        <button
          hx-delete="/admin/content/${item.id}"
          hx-confirm="Delete this content?"
          hx-target="closest .content-item"
          hx-swap="outerHTML"
        >
          Delete
        </button>
      </div>
    `)}
  `)
})

// HTMX endpoint for delete
app.delete('/admin/content/:id', async (c) => {
  const id = c.req.param('id')
  const db = c.env.DB

  await db.prepare('DELETE FROM content WHERE id = ?')
    .bind(id)
    .run()

  // Return empty response to remove element
  return c.html('')
})

export default app
```

---

## Summary

This documentation provides a comprehensive guide to routing and middleware in SonicJS AI:

1. **Middleware Pipeline**: Ordered execution from bootstrap through to route handlers
2. **Authentication**: Session-based auth (Better Auth) with requireAuth, requireRole, and optionalAuth
3. **Permissions**: Fine-grained permission system with requirePermission and requireAnyPermission
4. **Bootstrap**: One-time system initialization on worker startup
5. **Logging**: Request, security, and performance logging
6. **Performance**: Caching, compression, and security headers
7. **Plugins**: Route protection based on plugin activation
8. **Routes**: Complete route structure with examples
9. **Custom Middleware**: Patterns for creating your own middleware
10. **Examples**: Real-world examples combining multiple concepts

All middleware is designed to work with Cloudflare Workers' edge environment and Hono's lightweight framework.
