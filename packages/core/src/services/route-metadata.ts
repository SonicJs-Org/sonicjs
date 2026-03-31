/**
 * Route Metadata Service
 *
 * Auto-discovers API routes using Hono's inspectRoutes() and enriches them
 * with metadata from a static registry. Routes without metadata still appear
 * as "auto-discovered" — nothing is ever invisible.
 */

import { inspectRoutes } from 'hono/dev'

// ============================================================================
// Types
// ============================================================================

export interface RouteMetadata {
  method: string
  path: string
  description: string
  authentication: boolean | 'unknown'
  category: string
  documented: boolean
}

interface RouteMeta {
  description: string
  authentication: boolean
  category: string
}

export interface CategoryInfo {
  title: string
  description: string
  icon: string
}

// ============================================================================
// App Instance Storage
// ============================================================================

let appInstance: any = null

export function setAppInstance(app: any): void {
  appInstance = app
}

export function getAppInstance(): any {
  return appInstance
}

// ============================================================================
// Category Information
// ============================================================================

export const CATEGORY_INFO: Record<string, CategoryInfo> = {
  'Auth': {
    title: 'Authentication',
    description: 'User authentication and authorization endpoints',
    icon: '&#x1f510;'
  },
  'Content': {
    title: 'Content Management',
    description: 'Content creation, retrieval, and management',
    icon: '&#x1f4dd;'
  },
  'Media': {
    title: 'Media Management',
    description: 'File upload, storage, and media operations',
    icon: '&#x1f5bc;&#xfe0f;'
  },
  'Admin': {
    title: 'Admin Interface',
    description: 'Administrative panel and management features',
    icon: '&#x2699;&#xfe0f;'
  },
  'System': {
    title: 'System',
    description: 'Health checks and system information',
    icon: '&#x1f527;'
  },
  'Search': {
    title: 'Search',
    description: 'AI-powered search, full-text search, and analytics',
    icon: '&#x1f50d;'
  },
  'API Keys': {
    title: 'API Keys',
    description: 'API key management and authentication',
    icon: '&#x1f511;'
  },
  'Workflow': {
    title: 'Workflow',
    description: 'Content workflow and approval processes',
    icon: '&#x1f504;'
  },
  'Cache': {
    title: 'Cache',
    description: 'Cache management and invalidation',
    icon: '&#x26a1;'
  },
  'Forms': {
    title: 'Forms',
    description: 'Form submissions and management',
    icon: '&#x1f4cb;'
  },
  'Files': {
    title: 'Files',
    description: 'File serving from R2 storage',
    icon: '&#x1f4c1;'
  }
}

// ============================================================================
// Route Metadata Registry
// ============================================================================

const ROUTE_METADATA: Record<string, RouteMeta> = {
  // Auth endpoints
  'POST /auth/login': { description: 'Authenticate user with email and password (returns JWT)', category: 'Auth', authentication: false },
  'POST /auth/login/form': { description: 'Form-based login (sets session cookie)', category: 'Auth', authentication: false },
  'POST /auth/register': { description: 'Register a new user account', category: 'Auth', authentication: false },
  'POST /auth/logout': { description: 'Log out the current user and invalidate session', category: 'Auth', authentication: true },
  'GET /auth/me': { description: 'Get current authenticated user information', category: 'Auth', authentication: true },
  'POST /auth/refresh': { description: 'Refresh authentication token', category: 'Auth', authentication: true },
  'POST /auth/seed-admin': { description: 'Create or reset the admin user account', category: 'Auth', authentication: false },
  'POST /auth/magic-link/request': { description: 'Request a magic link login email', category: 'Auth', authentication: false },
  'GET /auth/magic-link/verify': { description: 'Verify magic link token and authenticate', category: 'Auth', authentication: false },
  'POST /auth/otp/request': { description: 'Request a one-time password via email', category: 'Auth', authentication: false },
  'POST /auth/otp/verify': { description: 'Verify OTP code and authenticate', category: 'Auth', authentication: false },

  // Content endpoints
  'GET /api/collections': { description: 'List all available collections', category: 'Content', authentication: false },
  'GET /api/collections/:collection/content': { description: 'Get all content items from a specific collection', category: 'Content', authentication: false },
  'GET /api/content/:id': { description: 'Get a specific content item by ID', category: 'Content', authentication: false },
  'POST /api/content': { description: 'Create a new content item', category: 'Content', authentication: true },
  'PUT /api/content/:id': { description: 'Update an existing content item', category: 'Content', authentication: true },
  'DELETE /api/content/:id': { description: 'Delete a content item', category: 'Content', authentication: true },
  'GET /api/content/:id/versions': { description: 'Get version history for a content item', category: 'Content', authentication: true },
  'POST /api/content/:id/restore/:versionId': { description: 'Restore a content item to a previous version', category: 'Content', authentication: true },

  // Media endpoints
  'GET /api/media': { description: 'List all media files with pagination', category: 'Media', authentication: false },
  'GET /api/media/:id': { description: 'Get a specific media file by ID', category: 'Media', authentication: false },
  'POST /api/media/upload': { description: 'Upload a new media file to R2 storage', category: 'Media', authentication: true },
  'DELETE /api/media/:id': { description: 'Delete a media file from storage', category: 'Media', authentication: true },

  // Admin API endpoints
  'GET /admin/api/stats': { description: 'Get dashboard statistics (collections, content, media, users)', category: 'Admin', authentication: true },
  'GET /admin/api/storage': { description: 'Get storage usage information', category: 'Admin', authentication: true },
  'GET /admin/api/activity': { description: 'Get recent activity logs', category: 'Admin', authentication: true },
  'GET /admin/api/collections': { description: 'List all collections with field counts', category: 'Admin', authentication: true },
  'POST /admin/api/collections': { description: 'Create a new collection', category: 'Admin', authentication: true },
  'GET /admin/api/collections/:id': { description: 'Get a specific collection with its fields', category: 'Admin', authentication: true },
  'PATCH /admin/api/collections/:id': { description: 'Update an existing collection', category: 'Admin', authentication: true },
  'DELETE /admin/api/collections/:id': { description: 'Delete a collection (must be empty)', category: 'Admin', authentication: true },
  'GET /admin/api/collections/:id/fields': { description: 'Get fields for a specific collection', category: 'Admin', authentication: true },
  'POST /admin/api/collections/:id/fields': { description: 'Add a field to a collection', category: 'Admin', authentication: true },
  'PATCH /admin/api/collections/:id/fields/:fieldId': { description: 'Update a collection field', category: 'Admin', authentication: true },
  'DELETE /admin/api/collections/:id/fields/:fieldId': { description: 'Remove a field from a collection', category: 'Admin', authentication: true },
  'POST /admin/api/collections/:id/fields/reorder': { description: 'Reorder fields in a collection', category: 'Admin', authentication: true },
  'GET /admin/api/migrations/status': { description: 'Get database migration status', category: 'Admin', authentication: true },
  'POST /admin/api/migrations/run': { description: 'Run pending database migrations', category: 'Admin', authentication: true },
  'GET /admin/api/content': { description: 'List content items with filtering and pagination', category: 'Admin', authentication: true },
  'GET /admin/api/content/:id': { description: 'Get a content item for admin editing', category: 'Admin', authentication: true },
  'POST /admin/api/content': { description: 'Create content via admin API', category: 'Admin', authentication: true },
  'PUT /admin/api/content/:id': { description: 'Update content via admin API', category: 'Admin', authentication: true },
  'DELETE /admin/api/content/:id': { description: 'Delete content via admin API', category: 'Admin', authentication: true },
  'GET /admin/api/media': { description: 'List media files for admin management', category: 'Admin', authentication: true },
  'POST /admin/api/media/upload': { description: 'Upload media via admin interface', category: 'Admin', authentication: true },
  'DELETE /admin/api/media/:id': { description: 'Delete media via admin interface', category: 'Admin', authentication: true },
  'GET /admin/api/users': { description: 'List all users', category: 'Admin', authentication: true },
  'POST /admin/api/users': { description: 'Create a new user', category: 'Admin', authentication: true },
  'PUT /admin/api/users/:id': { description: 'Update a user', category: 'Admin', authentication: true },
  'DELETE /admin/api/users/:id': { description: 'Delete a user', category: 'Admin', authentication: true },
  'GET /admin/api/logs': { description: 'Get application logs with filtering', category: 'Admin', authentication: true },
  'GET /admin/api/plugins': { description: 'List all registered plugins', category: 'Admin', authentication: true },
  'POST /admin/api/plugins/:id/toggle': { description: 'Enable or disable a plugin', category: 'Admin', authentication: true },
  'GET /admin/api/settings': { description: 'Get application settings', category: 'Admin', authentication: true },
  'PUT /admin/api/settings': { description: 'Update application settings', category: 'Admin', authentication: true },
  'GET /admin/api/forms': { description: 'List all forms', category: 'Admin', authentication: true },
  'GET /admin/api/forms/:id': { description: 'Get form details and submissions', category: 'Admin', authentication: true },
  'POST /admin/api/forms': { description: 'Create a new form', category: 'Admin', authentication: true },
  'PUT /admin/api/forms/:id': { description: 'Update a form', category: 'Admin', authentication: true },
  'DELETE /admin/api/forms/:id': { description: 'Delete a form', category: 'Admin', authentication: true },
  'GET /admin/api/forms/:id/submissions': { description: 'Get form submissions', category: 'Admin', authentication: true },
  'DELETE /admin/api/forms/:id/submissions/:submissionId': { description: 'Delete a form submission', category: 'Admin', authentication: true },

  // Search endpoints
  'GET /api/search': { description: 'Search content using AI, FTS5, keyword, or hybrid mode', category: 'Search', authentication: false },
  'POST /api/search/click': { description: 'Track a search result click for analytics', category: 'Search', authentication: false },
  'GET /admin/plugins/ai-search/api/status': { description: 'Get search plugin status and configuration', category: 'Search', authentication: true },
  'POST /admin/plugins/ai-search/api/index': { description: 'Trigger content indexing for search', category: 'Search', authentication: true },
  'POST /admin/plugins/ai-search/api/index/reset': { description: 'Reset the search index', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/analytics': { description: 'Get search analytics and metrics', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/analytics/queries': { description: 'Get top search queries', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/analytics/clicks': { description: 'Get click-through analytics', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/fts5/status': { description: 'Get FTS5 full-text search status', category: 'Search', authentication: true },
  'POST /admin/plugins/ai-search/api/fts5/rebuild': { description: 'Rebuild the FTS5 search index', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/facets': { description: 'Get available search facets', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/experiments': { description: 'List search A/B test experiments', category: 'Search', authentication: true },
  'POST /admin/plugins/ai-search/api/experiments': { description: 'Create a search A/B test experiment', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/experiments/:id': { description: 'Get experiment details', category: 'Search', authentication: true },
  'PUT /admin/plugins/ai-search/api/experiments/:id': { description: 'Update an experiment', category: 'Search', authentication: true },
  'DELETE /admin/plugins/ai-search/api/experiments/:id': { description: 'Delete an experiment', category: 'Search', authentication: true },
  'POST /admin/plugins/ai-search/api/experiments/:id/start': { description: 'Start an experiment', category: 'Search', authentication: true },
  'POST /admin/plugins/ai-search/api/experiments/:id/stop': { description: 'Stop a running experiment', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/experiments/:id/results': { description: 'Get experiment results and statistics', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/quality': { description: 'Get search quality agent analysis', category: 'Search', authentication: true },
  'POST /admin/plugins/ai-search/api/quality/run': { description: 'Run search quality analysis', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/quality/recommendations': { description: 'Get quality improvement recommendations', category: 'Search', authentication: true },
  'POST /admin/plugins/ai-search/api/quality/recommendations/:id/apply': { description: 'Apply a quality recommendation', category: 'Search', authentication: true },
  'POST /admin/plugins/ai-search/api/quality/recommendations/:id/dismiss': { description: 'Dismiss a quality recommendation', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/synonyms': { description: 'List search synonyms', category: 'Search', authentication: true },
  'POST /admin/plugins/ai-search/api/synonyms': { description: 'Add a search synonym', category: 'Search', authentication: true },
  'DELETE /admin/plugins/ai-search/api/synonyms/:id': { description: 'Delete a search synonym', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/query-rules': { description: 'List search query rules', category: 'Search', authentication: true },
  'POST /admin/plugins/ai-search/api/query-rules': { description: 'Create a query rule', category: 'Search', authentication: true },
  'PUT /admin/plugins/ai-search/api/query-rules/:id': { description: 'Update a query rule', category: 'Search', authentication: true },
  'DELETE /admin/plugins/ai-search/api/query-rules/:id': { description: 'Delete a query rule', category: 'Search', authentication: true },
  'GET /admin/plugins/ai-search/api/settings': { description: 'Get search plugin settings', category: 'Search', authentication: true },
  'PUT /admin/plugins/ai-search/api/settings': { description: 'Update search plugin settings', category: 'Search', authentication: true },

  // API Key endpoints
  'GET /admin/api-keys/api/keys': { description: 'List all API keys', category: 'API Keys', authentication: true },
  'POST /admin/api-keys/api/keys': { description: 'Create a new API key', category: 'API Keys', authentication: true },
  'DELETE /admin/api-keys/api/keys/:id': { description: 'Revoke an API key', category: 'API Keys', authentication: true },
  'PUT /admin/api-keys/api/keys/:id': { description: 'Update an API key', category: 'API Keys', authentication: true },

  // Cache endpoints
  'GET /admin/cache/api/stats': { description: 'Get cache statistics', category: 'Cache', authentication: true },
  'POST /admin/cache/api/purge': { description: 'Purge cache entries', category: 'Cache', authentication: true },
  'GET /admin/cache/api/entries': { description: 'List cache entries', category: 'Cache', authentication: true },
  'DELETE /admin/cache/api/entries/:key': { description: 'Delete a specific cache entry', category: 'Cache', authentication: true },

  // Workflow endpoints
  'GET /workflow/status/:id': { description: 'Get workflow status for a content item', category: 'Workflow', authentication: true },
  'POST /workflow/submit/:id': { description: 'Submit content for review', category: 'Workflow', authentication: true },
  'POST /workflow/approve/:id': { description: 'Approve content in review', category: 'Workflow', authentication: true },
  'POST /workflow/reject/:id': { description: 'Reject content in review', category: 'Workflow', authentication: true },
  'POST /workflow/publish/:id': { description: 'Publish approved content', category: 'Workflow', authentication: true },
  'POST /workflow/unpublish/:id': { description: 'Unpublish content', category: 'Workflow', authentication: true },
  'GET /workflow/history/:id': { description: 'Get workflow history for a content item', category: 'Workflow', authentication: true },

  // Form endpoints (public)
  'POST /forms/:formId/submit': { description: 'Submit a form (public endpoint)', category: 'Forms', authentication: false },
  'GET /forms/:formId': { description: 'Get form definition for rendering', category: 'Forms', authentication: false },
  'POST /api/forms/:formId/submit': { description: 'Submit a form via API', category: 'Forms', authentication: false },
  'GET /api/forms/:formId': { description: 'Get form definition via API', category: 'Forms', authentication: false },

  // System endpoints
  'GET /health': { description: 'Health check endpoint for monitoring', category: 'System', authentication: false },
  'GET /api/health': { description: 'API health check with schema information', category: 'System', authentication: false },
  'GET /api': { description: 'API root - returns API information and available endpoints', category: 'System', authentication: false },
  'GET /api/system/info': { description: 'Get system information and version', category: 'System', authentication: false },
  'GET /api/system/schema': { description: 'Get database schema information', category: 'System', authentication: false },

  // File serving
  'GET /files/*': { description: 'Serve files from R2 storage (public access)', category: 'Files', authentication: false },

  // Database tools
  'POST /admin/database-tools/api/query': { description: 'Execute a database query', category: 'Admin', authentication: true },
  'GET /admin/database-tools/api/tables': { description: 'List database tables', category: 'Admin', authentication: true },
  'GET /admin/database-tools/api/tables/:name': { description: 'Get table schema and sample data', category: 'Admin', authentication: true },

  // Seed data
  'POST /admin/seed-data/api/generate': { description: 'Generate seed data for development', category: 'Admin', authentication: true },
  'GET /admin/seed-data/api/status': { description: 'Get seed data generation status', category: 'Admin', authentication: true },

  // Email plugin
  'POST /admin/plugins/email/api/send': { description: 'Send an email', category: 'Admin', authentication: true },
  'GET /admin/plugins/email/api/templates': { description: 'List email templates', category: 'Admin', authentication: true },
  'POST /admin/plugins/email/api/test': { description: 'Send a test email', category: 'Admin', authentication: true },
}

// ============================================================================
// Whitelist Patterns for API routes
// ============================================================================

const INCLUDED_ROUTE_PATTERNS: RegExp[] = [
  /^\/api\//,                        // All /api/* routes
  /^\/api$/,                         // API root
  /^\/auth\/(?!login$|register$)/,   // Auth routes except GET login/register HTML pages
  /^\/auth\/login$/,                 // POST /auth/login (method filtered later)
  /^\/auth\/register$/,              // POST /auth/register (method filtered later)
  /^\/admin\/api\//,                 // Admin API endpoints
  /^\/admin\/api-keys\/api\//,       // API key management
  /^\/admin\/cache\/api\//,          // Cache management API
  /^\/admin\/plugins\/.*\/api\//,    // Plugin API endpoints
  /^\/admin\/database-tools\/api\//, // Database tools API
  /^\/admin\/seed-data\/api\//,      // Seed data API
  /^\/workflow\//,                   // Workflow endpoints
  /^\/health$/,                      // Health check
  /^\/files\//,                      // File serving
  /^\/forms\//,                      // Public form endpoints
]

// Routes to always exclude (even if they match an include pattern)
const EXCLUDED_ROUTES = new Set([
  'GET /auth/login',
  'GET /auth/register',
  'GET /auth/login/form',
])

// ============================================================================
// Route Discovery
// ============================================================================

let cachedRouteList: RouteMetadata[] | null = null

function isIncludedRoute(method: string, path: string): boolean {
  // Check exclusions first
  const key = `${method} ${path}`
  if (EXCLUDED_ROUTES.has(key)) {
    return false
  }

  // Check if the path matches any include pattern
  return INCLUDED_ROUTE_PATTERNS.some(pattern => pattern.test(path))
}

function inferCategory(path: string): string {
  if (path.startsWith('/auth/')) return 'Auth'
  if (path.startsWith('/api/search')) return 'Search'
  if (path.startsWith('/api/media')) return 'Media'
  if (path.startsWith('/api/system')) return 'System'
  if (path.startsWith('/api/content') || path.startsWith('/api/collections')) return 'Content'
  if (path.startsWith('/api/forms')) return 'Forms'
  if (path.startsWith('/admin/api-keys')) return 'API Keys'
  if (path.startsWith('/admin/cache')) return 'Cache'
  if (path.startsWith('/admin/plugins/ai-search')) return 'Search'
  if (path.startsWith('/admin/api')) return 'Admin'
  if (path.startsWith('/admin/database-tools')) return 'Admin'
  if (path.startsWith('/admin/seed-data')) return 'Admin'
  if (path.startsWith('/admin/plugins/email')) return 'Admin'
  if (path.startsWith('/workflow/')) return 'Workflow'
  if (path.startsWith('/forms/')) return 'Forms'
  if (path.startsWith('/files/')) return 'Files'
  if (path === '/health' || path.startsWith('/api')) return 'System'
  return 'Other'
}

function inferAuth(path: string): boolean | 'unknown' {
  // Known public routes
  if (path === '/health' || path === '/api' || path === '/api/health') return false
  if (path === '/api/system/info' || path === '/api/system/schema') return false
  if (path.startsWith('/files/')) return false
  if (path.startsWith('/forms/') || path.startsWith('/api/forms/')) return false

  // Admin routes require auth
  if (path.startsWith('/admin/')) return true
  if (path.startsWith('/workflow/')) return true

  return 'unknown'
}

export function buildRouteList(app: any): RouteMetadata[] {
  if (cachedRouteList) return cachedRouteList

  if (!app) return []

  try {
    const routes = inspectRoutes(app as any)

    // Deduplicate and filter
    const seen = new Set<string>()
    const result: RouteMetadata[] = []

    for (const route of routes) {
      // Skip middleware entries
      if (route.isMiddleware) continue
      // Skip ALL method (middleware-like catch-all)
      if (route.method === 'ALL') continue

      const key = `${route.method} ${route.path}`

      // Skip duplicates
      if (seen.has(key)) continue
      seen.add(key)

      // Apply whitelist filter
      if (!isIncludedRoute(route.method, route.path)) continue

      // Look up metadata
      const meta = ROUTE_METADATA[key]

      if (meta) {
        result.push({
          method: route.method,
          path: route.path,
          description: meta.description,
          authentication: meta.authentication,
          category: meta.category,
          documented: true
        })
      } else {
        // Auto-discovered: infer category and auth
        result.push({
          method: route.method,
          path: route.path,
          description: '',
          authentication: inferAuth(route.path),
          category: inferCategory(route.path),
          documented: false
        })
      }
    }

    // Sort: by category, then method order, then path
    const methodOrder: Record<string, number> = { GET: 0, POST: 1, PUT: 2, PATCH: 3, DELETE: 4 }
    result.sort((a, b) => {
      const catCmp = a.category.localeCompare(b.category)
      if (catCmp !== 0) return catCmp
      const methCmp = (methodOrder[a.method] ?? 5) - (methodOrder[b.method] ?? 5)
      if (methCmp !== 0) return methCmp
      return a.path.localeCompare(b.path)
    })

    cachedRouteList = result
    return result
  } catch (error) {
    console.error('Failed to inspect routes:', error)
    return []
  }
}
