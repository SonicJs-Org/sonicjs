# Architecture

**Analysis Date:** 2026-01-30

## Pattern Overview

**Overall:** Modular headless CMS built on Cloudflare Workers (edge runtime) with a plugin-first architecture. The app is a thin wrapper around the `@sonicjs-cms/core` framework that provides collection definitions, custom routes, and custom plugins.

**Key Characteristics:**
- Edge-first runtime (Cloudflare Workers via Wrangler)
- Plugin-based extensibility with lifecycle management
- Configuration-as-code for collections (declarative schemas)
- D1 database (SQLite) for persistence
- Separation between core framework (`@sonicjs-cms/core`) and application customizations
- Hono web framework for routing and middleware

## Layers

**Core Framework Layer:**
- Purpose: Provides reusable CMS infrastructure (routing, auth, collections, plugins, forms)
- Location: `@sonicjs-cms/core` (external package in `../packages/core`)
- Contains: Types, services, middleware, routes, plugin system, built-in plugins
- Depends on: Hono, Drizzle ORM, D1, R2, KV, Zod
- Used by: Application layer imports from this package

**Application Layer:**
- Purpose: Configures the SonicJS app with custom collections, routes, and plugins
- Location: `/Users/andrewhaas/Projects/SonicJS/sonicjs/my-sonicjs-app/src/index.ts`
- Contains: Hono app setup, collection registration, plugin mounting, configuration
- Depends on: Core framework, custom collections, custom plugins, routes
- Used by: Wrangler worker runtime

**Collections Layer:**
- Purpose: Define content schemas and metadata for managed data types
- Location: `/Users/andrewhaas/Projects/SonicJS/sonicjs/my-sonicjs-app/src/collections/`
- Contains: Collection configurations (JSON-like schema definitions)
- Depends on: `@sonicjs-cms/core` types
- Used by: Core app for content management UI and CRUD operations
- Examples: `blog-posts.collection.ts`, `page-blocks.collection.ts`, `contact-messages.collection.ts`

**Database Schema Layer:**
- Purpose: Define custom database tables using Drizzle ORM
- Location: `/Users/andrewhaas/Projects/SonicJS/sonicjs/my-sonicjs-app/src/db/schema/`
- Contains: Drizzle table definitions and TypeScript types
- Depends on: Drizzle ORM, D1
- Used by: Custom routes for data access
- Examples: `user-profiles.ts` extends the core user schema

**Routes Layer:**
- Purpose: Implement custom API endpoints beyond the core CMS
- Location: `/Users/andrewhaas/Projects/SonicJS/sonicjs/my-sonicjs-app/src/routes/`
- Contains: Hono route definitions with business logic
- Depends on: Hono, database, middleware, types
- Used by: Core app mounts routes via `app.route()`
- Examples: `profile.ts` provides profile CRUD API

**Plugins Layer:**
- Purpose: Extensible modules that add features with lifecycle management
- Location: `/Users/andrewhaas/Projects/SonicJS/sonicjs/my-sonicjs-app/src/plugins/`
- Contains: Custom plugins (e.g., contact-form with routes, services, components)
- Depends on: Core plugin system, database, services
- Used by: Core app mounts plugin routes during initialization
- Examples: `contact-form/` plugin with public form, admin settings, service layer

**Migration Layer:**
- Purpose: Database schema evolution and version control
- Location: `/Users/andrewhaas/Projects/SonicJS/sonicjs/my-sonicjs-app/migrations/`
- Contains: SQL migration files (001_initial_schema.sql, etc.)
- Depends on: D1 database
- Used by: Bootstrap middleware runs migrations on app start
- Examples: 31 migrations tracking schema from initial setup through plugin additions

## Data Flow

**Request Processing Flow:**

1. **Request arrives at Wrangler** (Cloudflare Worker)
2. **Middleware pipeline** in `src/index.ts`:
   - App version middleware sets `appVersion` in context
   - Metrics middleware tracks request metrics
   - Bootstrap middleware (from core) runs migrations, syncs collections, initializes plugins
   - Auth middleware (from core) validates JWT tokens and populates `c.get('user')`
3. **Route matching** via Hono:
   - Plugin routes matched first (`/contact`, `/api/contact`, `/admin/plugins/contact-form/*`)
   - Core routes matched second (CRUD, media, admin, auth)
   - 404 if no match
4. **Request handling**:
   - Routes access DB via `c.env.DB` or Drizzle `drizzle(c.env.DB)`
   - Routes may instantiate services (`new ContactService(db)`)
   - Services interact with database (queries, inserts, updates)
5. **Response returns** through middleware and back to client

**Collection Management Flow:**

1. **App startup** runs `registerCollections()` in `src/index.ts`
2. **Collection configs** loaded from `src/collections/` (static registration)
3. **Core bootstrap middleware** syncs collection schemas to database
4. **Admin UI** (in core) renders CRUD forms based on collection schemas
5. **Content API** (in core) provides CRUD endpoints for each collection

**Plugin Initialization Flow:**

1. **App startup** creates plugin instances and stores in context
2. **Plugin lifecycle hooks** called in order: install → activate → configure
3. **Plugin routes** mounted into main Hono app via `app.route(path, handler)`
4. **Plugin services** instantiated per request and passed to route handlers
5. **Plugin deactivation** removes from active plugins list but doesn't uninstall

**State Management:**

- **User state:** JWT token parsed and stored in `c.get('user')` via auth middleware
- **Request state:** Context variables (`Bindings`, `Variables`) passed through request lifecycle
- **Database state:** Persisted to D1, accessed via raw SQL queries or Drizzle ORM
- **Plugin state:** Settings stored in `plugins` table as JSON, loaded on-demand by services
- **Cache state:** Optional KV namespace (`CACHE_KV`) for caching, not heavily utilized in current code

## Key Abstractions

**Collection:**
- Purpose: Declarative schema definition for a content type
- Examples: `blog-posts.collection.ts`, `contact-messages.collection.ts`
- Pattern: Object with `name`, `displayName`, `schema`, `listFields`, `searchFields` properties
- File: `src/collections/*.collection.ts`

**Plugin:**
- Purpose: Modular feature with routes, services, settings, and lifecycle hooks
- Examples: `contact-form/` plugin
- Pattern: Class extending `PluginBuilder`, supports routes, services, admin pages, menu items, lifecycle hooks
- Files: `src/plugins/contact-form/index.ts` (main), with sub-directories for routes, services, components

**PluginService:**
- Purpose: Encapsulates business logic for a plugin (database access, external APIs)
- Examples: `ContactService` in `src/plugins/contact-form/services/contact.ts`
- Pattern: Class constructor takes `D1Database`, implements async methods for domain operations
- Methods: `getSettings()`, `saveSettings()`, `saveMessage()`, `getMessages()`, lifecycle methods

**Route Handler:**
- Purpose: HTTP endpoint implementation
- Examples: `publicRoutes.get('/contact')`, `publicRoutes.post('/api/contact')`
- Pattern: Hono route with async context handler, accesses `c.env.DB` or services
- File: `src/plugins/*/routes/*.ts` or `src/routes/*.ts`

**Schema:**
- Purpose: JSON schema describing content structure for forms and validation
- Used in: Collections and plugin forms
- Pattern: Objects with `type`, `properties`, `required`, custom field types (slug, media, quill, etc.)
- File: Collection definitions include full nested schemas

## Entry Points

**Application Entry:**
- Location: `/Users/andrewhaas/Projects/SonicJS/sonicjs/my-sonicjs-app/src/index.ts`
- Triggers: Wrangler worker startup
- Responsibilities:
  - Create Hono app
  - Register collections
  - Mount plugin routes
  - Mount core app as catch-all route
  - Export as default export for Wrangler

**Core Framework Entry:**
- Location: `@sonicjs-cms/core` → `packages/core/src/index.ts`
- Triggers: Imported by application
- Responsibilities:
  - Export factory functions (`createSonicJSApp`)
  - Export middleware, services, types
  - Initialize built-in plugins and routes

**Request Entry Points (Routes):**
- Public form endpoint: `GET /contact`, `POST /api/contact` (contact-form plugin)
- Admin plugin settings: `/admin/plugins/contact-form/*` (requires auth)
- User profile API: `GET /api/profile`, `PUT /api/profile`, `PATCH /api/profile`, `DELETE /api/profile`
- Core CMS endpoints: All `/api/*`, `/admin/*` (provided by core)

**Database Entry Point:**
- Location: Cloudflare D1 binding `DB` in Wrangler config
- Accessed via: `c.env.DB` (raw SQL) or `drizzle(c.env.DB)` (ORM)
- Migrations: Applied via `wrangler d1 migrations apply DB --local`

## Error Handling

**Strategy:** Try-catch blocks in route handlers and services with console.error logging and JSON error responses

**Patterns:**

**Route Handler Errors:**
```typescript
// Example from src/plugins/contact-form/routes/public.ts
try {
  const db = c.get('db') || c.env?.DB
  if (!db) {
    return c.html('<h1>Service temporarily unavailable</h1>', 503)
  }
  // ... route logic
} catch (error) {
  console.error('Error rendering contact page:', error)
  return c.html('<h1>Error loading contact form</h1>', 500)
}
```

**Service Errors:**
```typescript
// Example from src/plugins/contact-form/services/contact.ts
async saveMessage(data: ContactMessage): Promise<void> {
  try {
    if (!this.db) {
      throw new Error('Database not available')
    }
    // ... service logic
  } catch (error) {
    console.error('Error saving contact message - Full error:', error)
    throw error
  }
}
```

**Validation Errors:**
```typescript
// Basic field validation in route handlers
if (!data.name || !data.email || !data.msg) {
  return c.json({
    success: false,
    error: 'All fields are required'
  }, 400)
}
```

## Cross-Cutting Concerns

**Logging:**
- Approach: Console.log/console.error for debugging and errors
- Patterns: Prefixed logs with component/function name `[ContactService.saveSettings]`
- File: Distributed across service and route files

**Validation:**
- Approach: Type-based via TypeScript + Zod in core, runtime checks in routes
- Patterns:
  - Type guards in route handlers (check required fields exist)
  - Schema validation in collection definitions
  - Turnstile CAPTCHA verification in contact form routes
- Files: Collection schemas, route handlers, contact form public routes

**Authentication:**
- Approach: JWT tokens via middleware (core framework provides)
- Patterns: `requireAuth()` middleware decorator on routes
- File: Applied to profile routes via `profileRoutes.use('*', requireAuth())`
- User context: Injected via `c.get('user')` containing `userId`, `email`, `role`, `exp`, `iat`

**Authorization:**
- Approach: Role-based (admin/user) and permission-based access control (core framework)
- Patterns: Plugin routes can specify `requiresAuth: true` and required permissions
- File: Plugin definitions like contact-form require `['admin', 'contact_form.manage']` for admin routes

**Database Access:**
- Pattern: Direct D1 SQL queries via `db.prepare().bind().first()` or `.all()`
- Alternative: Drizzle ORM via `drizzle(c.env.DB).select().from(table).where()`
- File: Services in `src/plugins/*/services/`, routes in `src/routes/`

**Content Type Detection:**
- Approach: Check `Content-Type` header and parse accordingly
- Pattern: In form routes, support JSON, form-urlencoded, and multipart/form-data
- File: `src/plugins/contact-form/routes/public.ts` line 207-216

---

*Architecture analysis: 2026-01-30*
