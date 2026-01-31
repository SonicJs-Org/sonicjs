# @sonicjs-cms/core API Reference

**Version**: 2.0.2
**Status**: Stable Release
**Last Updated**: October 24, 2025

## Table of Contents

1. [Installation](#installation)
2. [Core Application](#core-application)
3. [Services](#services)
4. [Middleware](#middleware)
5. [Routes](#routes)
6. [Templates](#templates)
7. [Utilities](#utilities)
8. [Database](#database)
9. [Types](#types)
10. [Plugins](#plugins)

---

## Installation

```bash
# Install via npm
npm install @sonicjs-cms/core

# Install via pnpm
pnpm add @sonicjs-cms/core

# Install via yarn
yarn add @sonicjs-cms/core
```

### Peer Dependencies

The core package requires these peer dependencies:

```json
{
  "@cloudflare/workers-types": "^4.0.0",
  "hono": "^4.0.0",
  "drizzle-orm": "^0.44.0",
  "zod": "^3.0.0"
}
```

---

## Core Application

### createSonicJSApp

Creates a new SonicJS application instance.

```typescript
import { createSonicJSApp } from '@sonicjs-cms/core'

const app = createSonicJSApp({
  collections: './src/collections',
  plugins: './src/plugins',
  routes: './src/routes',
  templates: './src/templates'
})
```

**Parameters:**
- `config`: `SonicJSConfig` - Application configuration object

**Returns:** `SonicJSApp` - Configured Hono application

### setupCoreMiddleware

Configures all core middleware for the application.

```typescript
import { setupCoreMiddleware } from '@sonicjs-cms/core'

setupCoreMiddleware(app, env)
```

### setupCoreRoutes

Mounts all core routes to the application.

```typescript
import { setupCoreRoutes } from '@sonicjs-cms/core'

setupCoreRoutes(app)
```

---

## Services

### Collection Management

#### loadCollectionConfigs

Loads all collection configuration files from the specified directory.

```typescript
import { loadCollectionConfigs } from '@sonicjs-cms/core'

const configs = await loadCollectionConfigs('./src/collections')
```

#### syncCollections

Synchronizes collection configurations with the database.

```typescript
import { syncCollections } from '@sonicjs-cms/core'

const result = await syncCollections(db)
```

**Parameters:**
- `db`: `D1Database` - Cloudflare D1 database instance

**Returns:** `Promise<CollectionSyncResult>`

#### fullCollectionSync

Performs a complete synchronization including cleanup of removed collections.

```typescript
import { fullCollectionSync } from '@sonicjs-cms/core'

const result = await fullCollectionSync(db)
```

### Migration Service

#### MigrationService

Class for managing database migrations.

```typescript
import { MigrationService } from '@sonicjs-cms/core'

const migrationService = new MigrationService(db)
await migrationService.runPendingMigrations()
```

**Methods:**
- `getMigrationStatus()` - Get current migration status
- `runPendingMigrations()` - Apply all pending migrations
- `rollbackMigration(migrationId)` - Rollback a specific migration

### Logging

#### Logger

Core logging service for the application.

```typescript
import { getLogger } from '@sonicjs-cms/core'

const logger = getLogger(db)

await logger.info('system', 'Application started')
await logger.error('auth', 'Login failed', error)
await logger.debug('cache', 'Cache hit', { key, value })
```

**Log Levels:** `debug`, `info`, `warn`, `error`

**Log Categories:** `system`, `auth`, `content`, `media`, `plugin`, `cache`, `api`

### Plugin Services

#### PluginService

Manages plugin lifecycle and operations.

```typescript
import { PluginServiceClass } from '@sonicjs-cms/core'

const pluginService = new PluginServiceClass(db)
await pluginService.registerPlugin(plugin)
await pluginService.activatePlugin('plugin-name')
```

#### PluginBootstrapService

Handles initial plugin setup and bootstrapping.

```typescript
import { PluginBootstrapService } from '@sonicjs-cms/core'

const bootstrap = new PluginBootstrapService(db)
await bootstrap.bootstrapCorePlugins()
```

---

## Middleware

### Authentication

#### requireAuth

Middleware that requires valid session authentication (Better Auth). Reads `user` from context set by global session middleware.

```typescript
import { requireAuth } from '@sonicjs-cms/core'

app.use('/admin/*', requireAuth())
```

#### requireRole

Middleware that requires specific user roles.

```typescript
import { requireRole } from '@sonicjs-cms/core'

app.use('/admin/*', requireRole(['admin', 'editor']))
```

#### optionalAuth

Middleware that adds user context if authenticated, but doesn't require it.

```typescript
import { optionalAuth } from '@sonicjs-cms/core'

app.use('/api/*', optionalAuth())
```

### AuthManager

Static class for legacy auth operations (e.g. seed-admin). Sign-in/sign-up use Better Auth; do not use `generateToken`/`verifyToken` for new features.

```typescript
import { AuthManager } from '@sonicjs-cms/core'

// Hash password (legacy flows only)
const hash = await AuthManager.hashPassword('password123')

// Verify password (legacy flows only)
const valid = await AuthManager.verifyPassword('password123', hash)
```

### Logging Middleware

#### loggingMiddleware

Basic request logging middleware.

```typescript
import { loggingMiddleware } from '@sonicjs-cms/core'

app.use('*', loggingMiddleware())
```

#### detailedLoggingMiddleware

Detailed request/response logging with timing.

```typescript
import { detailedLoggingMiddleware } from '@sonicjs-cms/core'

app.use('*', detailedLoggingMiddleware())
```

#### securityLoggingMiddleware

Logs security-related events and suspicious activity.

```typescript
import { securityLoggingMiddleware } from '@sonicjs-cms/core'

app.use('*', securityLoggingMiddleware())
```

#### performanceLoggingMiddleware

Logs slow requests that exceed a threshold.

```typescript
import { performanceLoggingMiddleware } from '@sonicjs-cms/core'

// Log requests slower than 1000ms
app.use('*', performanceLoggingMiddleware(1000))
```

### Performance Middleware

#### cacheHeaders

Adds cache control headers to responses.

```typescript
import { cacheHeaders } from '@sonicjs-cms/core'

// Cache for 60 seconds
app.use('/api/*', cacheHeaders(60))
```

#### compressionMiddleware

Compresses responses using gzip/brotli.

```typescript
import { compressionMiddleware } from '@sonicjs-cms/core'

app.use('*', compressionMiddleware)
```

#### securityHeaders

Adds security headers to all responses.

```typescript
import { securityHeaders } from '@sonicjs-cms/core'

app.use('*', securityHeaders())
```

### Permissions

#### requirePermission

Requires a specific permission for the route.

```typescript
import { requirePermission } from '@sonicjs-cms/core'

app.get('/admin/users', requirePermission('users.read'), handler)
```

#### requireAnyPermission

Requires any one of the specified permissions.

```typescript
import { requireAnyPermission } from '@sonicjs-cms/core'

app.get('/content', requireAnyPermission(['content.read', 'content.write']), handler)
```

#### PermissionManager

Static class for permission management.

```typescript
import { PermissionManager } from '@sonicjs-cms/core'

// Check permission
const hasPermission = await PermissionManager.hasPermission(db, userId, 'users.write')

// Grant permission
await PermissionManager.grantPermission(db, userId, 'content.delete')

// Revoke permission
await PermissionManager.revokePermission(db, userId, 'content.delete')
```

### Plugin Middleware

#### requireActivePlugin

Requires a plugin to be active for the route.

```typescript
import { requireActivePlugin } from '@sonicjs-cms/core'

app.use('/admin/workflow/*', requireActivePlugin('workflow'))
```

#### getActivePlugins

Gets list of currently active plugins.

```typescript
import { getActivePlugins } from '@sonicjs-cms/core'

const plugins = await getActivePlugins(db)
```

### Bootstrap

#### bootstrapMiddleware

Initializes the application on first request.

```typescript
import { bootstrapMiddleware } from '@sonicjs-cms/core'

app.use('*', bootstrapMiddleware())
```

---

## Routes

All routes are pre-configured and ready to mount.

### API Routes

```typescript
import {
  apiRoutes,
  apiContentCrudRoutes,
  apiMediaRoutes,
  apiSystemRoutes
} from '@sonicjs-cms/core'

app.route('/api', apiRoutes)
app.route('/api', apiContentCrudRoutes)
app.route('/api/media', apiMediaRoutes)
app.route('/api', apiSystemRoutes)
```

### Admin Routes

```typescript
import {
  adminDashboardRoutes,
  adminContentRoutes,
  adminUsersRoutes,
  adminMediaRoutes,
  adminPluginRoutes,
  adminLogsRoutes,
  adminCollectionsRoutes,
  adminSettingsRoutes
} from '@sonicjs-cms/core'

app.route('/admin', adminDashboardRoutes)
app.route('/admin/content', adminContentRoutes)
app.route('/admin', adminUsersRoutes)
app.route('/admin/media', adminMediaRoutes)
app.route('/admin/plugins', adminPluginRoutes)
app.route('/admin/logs', adminLogsRoutes)
app.route('/admin', adminCollectionsRoutes)
app.route('/admin', adminSettingsRoutes)
```

### Auth Routes

```typescript
import { authRoutes } from '@sonicjs-cms/core'

app.route('/auth', authRoutes)
```

---

## Templates

### Form Templates

#### renderForm

Renders a complete form with validation.

```typescript
import { renderForm } from '@sonicjs-cms/core'

const html = renderForm({
  action: '/admin/users/new',
  method: 'POST',
  fields: [
    { name: 'email', label: 'Email', type: 'email', required: true },
    { name: 'password', label: 'Password', type: 'password', required: true }
  ],
  submitLabel: 'Create User'
})
```

#### renderFormField

Renders a single form field.

```typescript
import { renderFormField } from '@sonicjs-cms/core'

const html = renderFormField({
  name: 'title',
  label: 'Title',
  type: 'text',
  value: 'My Title',
  required: true,
  placeholder: 'Enter title...'
})
```

### Table Templates

#### renderTable

Renders a data table with sorting and pagination.

```typescript
import { renderTable } from '@sonicjs-cms/core'

const html = renderTable({
  columns: [
    { key: 'name', label: 'Name', sortable: true },
    { key: 'email', label: 'Email', sortable: true },
    { key: 'role', label: 'Role' }
  ],
  rows: users,
  sortBy: 'name',
  sortOrder: 'asc'
})
```

### Pagination Templates

#### renderPagination

Renders pagination controls.

```typescript
import { renderPagination } from '@sonicjs-cms/core'

const html = renderPagination({
  currentPage: 1,
  totalPages: 10,
  totalItems: 100,
  itemsPerPage: 10,
  baseUrl: '/admin/users'
})
```

### Alert Templates

#### renderAlert

Renders an alert message.

```typescript
import { renderAlert } from '@sonicjs-cms/core'

const html = renderAlert({
  type: 'success',
  message: 'User created successfully!',
  dismissible: true
})
```

**Alert Types:** `success`, `error`, `warning`, `info`

### Dialog Templates

#### renderConfirmationDialog

Renders a confirmation dialog.

```typescript
import { renderConfirmationDialog } from '@sonicjs-cms/core'

const html = renderConfirmationDialog({
  title: 'Delete User?',
  message: 'Are you sure you want to delete this user?',
  confirmText: 'Delete',
  cancelText: 'Cancel',
  onConfirm: '/admin/users/123/delete'
})
```

---

## Utilities

### Sanitization

#### sanitizeInput

Sanitizes user input to prevent XSS attacks.

```typescript
import { sanitizeInput } from '@sonicjs-cms/core'

const clean = sanitizeInput(userInput)
```

#### sanitizeObject

Recursively sanitizes all string values in an object.

```typescript
import { sanitizeObject } from '@sonicjs-cms/core'

const cleanData = sanitizeObject(userData)
```

#### escapeHtml

Escapes HTML special characters.

```typescript
import { escapeHtml } from '@sonicjs-cms/core'

const safe = escapeHtml('<script>alert("xss")</script>')
// Result: &lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;
```

### Template Rendering

#### TemplateRenderer

Class for rendering Handlebars-like templates.

```typescript
import { TemplateRenderer } from '@sonicjs-cms/core'

const renderer = new TemplateRenderer()
const html = renderer.render(template, data)
```

#### renderTemplate

Quick template rendering function.

```typescript
import { renderTemplate } from '@sonicjs-cms/core'

const html = renderTemplate('Hello {{name}}!', { name: 'World' })
```

### Query Filtering

#### QueryFilterBuilder

Builds complex database queries.

```typescript
import { QueryFilterBuilder } from '@sonicjs-cms/core'

const builder = new QueryFilterBuilder()
const query = builder
  .where('status', '=', 'published')
  .where('author', '=', userId)
  .orderBy('created_at', 'desc')
  .limit(10)
  .build()
```

#### buildQuery

Quick query building function.

```typescript
import { buildQuery } from '@sonicjs-cms/core'

const { sql, params } = buildQuery({
  table: 'content',
  where: [
    { field: 'status', operator: '=', value: 'published' }
  ],
  orderBy: 'created_at',
  order: 'desc',
  limit: 10
})
```

### Metrics

#### metricsTracker

Tracks application metrics.

```typescript
import { metricsTracker } from '@sonicjs-cms/core'

metricsTracker.recordRequest()
metricsTracker.recordError()

const metrics = metricsTracker.getMetrics()
```

### Version

#### getCoreVersion

Gets the current core package version.

```typescript
import { getCoreVersion, SONICJS_VERSION } from '@sonicjs-cms/core'

console.log(getCoreVersion()) // "2.0.2"
console.log(SONICJS_VERSION)  // "2.0.2"
```

---

## Database

### Schema Creation

#### createDb

Creates a typed Drizzle database instance.

```typescript
import { createDb } from '@sonicjs-cms/core'

const db = createDb(env.DB)
```

### Schema Tables

All core database tables are exported:

```typescript
import {
  users,
  collections,
  content,
  contentVersions,
  media,
  apiTokens,
  workflowHistory,
  plugins,
  pluginHooks,
  pluginRoutes,
  systemLogs
} from '@sonicjs-cms/core'

// Query with Drizzle ORM
const allUsers = await db.select().from(users).all()
const activeContent = await db
  .select()
  .from(content)
  .where(eq(content.status, 'published'))
  .all()
```

### Zod Validation Schemas

Validation schemas for all tables:

```typescript
import {
  insertUserSchema,
  selectUserSchema,
  insertContentSchema,
  selectContentSchema
} from '@sonicjs-cms/core'

// Validate user data
const validatedUser = insertUserSchema.parse(userData)
```

---

## Types

### Collection Types

```typescript
import type {
  CollectionConfig,
  CollectionSchema,
  FieldType,
  FieldConfig
} from '@sonicjs-cms/core'
```

### Plugin Types

```typescript
import type {
  Plugin,
  PluginContext,
  PluginConfig,
  PluginHook,
  HookHandler,
  PluginManifest
} from '@sonicjs-cms/core'
```

### Database Types

```typescript
import type {
  User,
  NewUser,
  Content,
  NewContent,
  Media,
  NewMedia
} from '@sonicjs-cms/core'
```

---

## Plugins

### Hook System

#### HookSystemImpl

Core hook system implementation.

```typescript
import { HookSystemImpl } from '@sonicjs-cms/core'

const hookSystem = new HookSystemImpl()
hookSystem.register('content:beforeSave', async (data) => {
  // Modify data before save
  return data
})

const result = await hookSystem.execute('content:beforeSave', content)
```

### Plugin Registry

#### PluginRegistryImpl

Registry for managing plugins.

```typescript
import { PluginRegistryImpl } from '@sonicjs-cms/core'

const registry = new PluginRegistryImpl()
await registry.register(plugin)
const allPlugins = registry.getAll()
```

### Plugin Manager

#### PluginManagerClass

Manages plugin lifecycle.

```typescript
import { PluginManagerClass } from '@sonicjs-cms/core'

const manager = new PluginManagerClass(db, registry, hookSystem)
await manager.activatePlugin('plugin-name')
await manager.deactivatePlugin('plugin-name')
```

---

## Usage Examples

### Complete Application Setup

```typescript
import { Hono } from 'hono'
import {
  setupCoreMiddleware,
  setupCoreRoutes,
  apiRoutes,
  adminDashboardRoutes,
  authRoutes,
  requireAuth
} from '@sonicjs-cms/core'

const app = new Hono()

// Setup middleware
setupCoreMiddleware(app, env)

// Mount auth routes (public)
app.route('/auth', authRoutes)

// Mount API routes (optional auth)
app.use('/api/*', optionalAuth())
app.route('/api', apiRoutes)

// Mount admin routes (requires auth)
app.use('/admin/*', requireAuth())
app.use('/admin/*', requireRole(['admin', 'editor']))
app.route('/admin', adminDashboardRoutes)

export default app
```

### Custom Collection

```typescript
import type { CollectionConfig } from '@sonicjs-cms/core'

export const productsCollection: CollectionConfig = {
  name: 'products',
  displayName: 'Products',
  description: 'E-commerce products',
  schema: {
    type: 'object',
    properties: {
      name: { type: 'string', required: true },
      price: { type: 'number', required: true },
      description: { type: 'richtext' },
      image: { type: 'media' },
      inStock: { type: 'boolean', default: true }
    }
  },
  managed: true,
  isActive: true
}
```

### Custom Plugin

```typescript
import type { Plugin, PluginContext } from '@sonicjs-cms/core'

const myPlugin: Plugin = {
  name: 'my-custom-plugin',
  version: '1.0.0',
  description: 'My custom plugin',

  async install(context: PluginContext) {
    // Installation logic
  },

  async activate(context: PluginContext) {
    // Register hooks
    context.hookSystem.register('content:beforeSave', async (data) => {
      // Custom logic
      return data
    })
  },

  async deactivate(context: PluginContext) {
    // Cleanup logic
  }
}

export default myPlugin
```

---

## Version History

### 2.0.2 (Current)
- User management routes added
- Permission system integration
- Admin route consolidation
- Bug fixes and stability improvements

### 2.0.1
- Initial stable release
- Core routes extracted
- Template system complete
- Plugin system functional

### 2.0.0
- Initial alpha release
- Core package extraction
- Basic functionality

---

## Support & Resources

- **Documentation**: https://docs.sonicjs.com
- **GitHub**: https://github.com/sonicjs/sonicjs
- **Issues**: https://github.com/sonicjs/sonicjs/issues
- **NPM**: https://www.npmjs.com/package/@sonicjs-cms/core

---

**Last Updated**: October 24, 2025
**Package Version**: 2.0.2
**License**: MIT
