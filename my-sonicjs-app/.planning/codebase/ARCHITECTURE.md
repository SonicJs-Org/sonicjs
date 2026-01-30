# Architecture

**Analysis Date:** 2026-01-30

## Pattern Overview

**Overall:** Plugin-based Headless CMS on Cloudflare Workers with Layered Application Architecture

**Key Characteristics:**
- Edge-first: Runs on Cloudflare Workers (serverless edge computing)
- Plugin-extensible: Core CMS engine with optional plugins for features
- Config-driven collections: Content schemas defined as code via TypeScript interfaces
- Database-agnostic ORM layer: Drizzle ORM for D1 (SQLite) database abstraction
- Middleware-based request handling: Hono.js web framework with composable middleware
- Type-safe: Full TypeScript with strict mode across application

## Layers

**Edge Runtime (Cloudflare Workers):**
- Purpose: HTTP request handling and response serving at edge locations
- Location: `src/index.ts` (entry point mounted with Hono)
- Contains: Route handlers, middleware chains, request/response processing
- Depends on: Hono framework, core SonicJS app
- Used by: Client browsers, API consumers

**Application Layer (Hono routing):**
- Purpose: Route registration, plugin mounting, request routing
- Location: `src/index.ts`
- Contains: Core app creation via `createSonicJSApp()`, manual plugin route mounting, app composition
- Depends on: Hono, @sonicjs-cms/core
- Used by: Edge runtime

**Plugin System:**
- Purpose: Modular feature implementation through plugin architecture
- Location: `src/plugins/*/` directory structure
- Contains: Plugin definitions (index.ts), routes, services, lifecycle hooks, manifests
- Depends on: PluginBuilder from @sonicjs-cms/core, Hono for routing
- Used by: Application layer, admin interface, API consumers
- Plugins register themselves via PluginBuilder API with metadata, routes, admin pages, menu items

**Service Layer:**
- Purpose: Business logic encapsulation and database operations
- Location: `src/plugins/*/services/` (e.g., `src/plugins/contact-form/services/contact.ts`)
- Contains: Domain-specific operations (ContactService for contact forms)
- Depends on: D1 Database, domain models/types
- Used by: Routes, plugin lifecycle hooks
- Pattern: Service classes accept D1Database instance in constructor, expose async methods for CRUD

**Route Layer:**
- Purpose: HTTP endpoint handling with middleware composition
- Location: `src/plugins/*/routes/` (e.g., `src/plugins/contact-form/routes/public.ts`, `routes/admin.ts`)
- Contains: Hono Router instances, request handlers, form rendering, API logic
- Depends on: Hono, Services, D1 Database context
- Used by: Plugin system for mounting
- Pattern: Public routes (no auth) and admin routes (requiresAuth) separated by file

**Database Layer:**
- Purpose: Data persistence and schema definition
- Location: `src/db/schema/` (app extensions), core schemas in @sonicjs-cms/core
- Contains: Drizzle ORM table definitions (`userProfiles`), Drizzle relations
- Depends on: Drizzle ORM, D1 (Cloudflare Workers SQLite)
- Used by: Services via D1Database binding
- Pattern: Schemas defined as Drizzle tables with TypeScript inference for type safety

**Collection System:**
- Purpose: Content type definitions and admin UI configuration
- Location: `src/collections/*.collection.ts`
- Contains: CollectionConfig objects defining schema, fields, list view settings, search
- Depends on: @sonicjs-cms/core types
- Used by: Core admin interface for list views, data validation, API schema generation
- Pattern: Configuration as code - each collection is exported as satisfying CollectionConfig type

**Middleware Stack:**
- Purpose: Cross-cutting concerns like authentication, logging, database binding
- Location: Routes and app initialization
- Contains: requireAuth() middleware, DB context injection, request/response handling
- Depends on: Hono middleware API, auth from core
- Used by: Route handlers for request processing

## Data Flow

**User Submits Contact Form:**

1. User visits `/contact` (public GET)
2. `publicRoutes.get('/contact')` in `src/plugins/contact-form/routes/public.ts` renders HTML form
3. Form includes ContactService call to `getSettings()` - loads config from plugins DB table
4. HTML returned with Bootstrap styling, Google Maps iframe (if enabled), Turnstile widget (if enabled)
5. User submits form (POST to `/api/contact`)
6. Middleware validates content-type and parses JSON/FormData
7. ContactService validates required fields (name, email, msg)
8. If Turnstile enabled: Fetch Cloudflare API to verify token
9. ContactService.saveMessage() creates content record in database:
   - Finds contact_messages collection ID from collections table
   - Finds first active admin user
   - INSERTs into content table with collection_id, slug, data (JSON), author_id
10. Returns JSON success response
11. Client-side JavaScript shows success alert and resets form

**Admin Views Settings:**

1. Authenticated admin navigates to `/admin/plugins/contact-form/settings`
2. Admin route handler in `src/plugins/contact-form/routes/admin.ts` renders settings page
3. Settings page is a component from `src/plugins/contact-form/components/settings-page.ts`
4. On form submit: POST to admin endpoint
5. ContactService.saveSettings() updates/inserts plugins table row with JSON settings
6. Settings persisted with status flag (active/inactive)

**App Initialization:**

1. Cloudflare Worker invokes edge function at `src/index.ts`
2. Collections registered: `registerCollections([...])` loads collection definitions
3. SonicJS config created with collection settings, plugin directory, enabled plugins list
4. Core app created: `createSonicJSApp(config)` - initializes admin UI, API routes, auth
5. Custom Hono instance created for plugin mounting
6. Contact form plugin routes manually mounted (plugin.routes array iteration)
7. Core app mounted as catch-all at `/`
8. App exported as default for Wrangler deployment

**State Management:**

- Plugin Configuration State: Persisted in D1 plugins table as JSON settings with status
- Content Data: Stored in D1 content table with collection_id references
- User Authentication: Managed by core SonicJS (@sonicjs-cms/core) via middleware
- Request Context: D1 database binding injected via Hono context, accessible to handlers
- Client-side: Form success/error state managed via DOM (hidden/shown classes)

## Key Abstractions

**Plugin:**
- Purpose: Encapsulate feature functionality (contact form, email, etc.) with routes, services, lifecycle
- Examples: `src/plugins/contact-form/index.ts`
- Pattern: PluginBuilder fluent API - create > metadata > addRoute > addService > lifecycle > build
- Lifecycle Hooks: install, activate, deactivate, uninstall, configure
- Routes can specify requiresAuth and priority
- Admin pages registered with icon and permissions

**Collection:**
- Purpose: Define content type structure, validation, admin UI configuration without code
- Examples: `src/collections/blog-posts.collection.ts`, `src/collections/contact-messages.collection.ts`
- Pattern: satisfies CollectionConfig - validates schema at type-check time
- Schema format: JSON Schema with custom field types (media, quill, slug, etc.)
- Features: listFields for admin view, searchFields for search, defaultSort/Order, managed flag

**Service:**
- Purpose: Encapsulate domain business logic and database operations
- Examples: `src/plugins/contact-form/services/contact.ts`
- Pattern: Class constructor takes D1Database, exposes async methods, returns typed responses
- Methods pattern: getSettings() -> {status, data}, saveMessage(data) -> void/throws
- Error handling: Try-catch with console.error logging and error throwing

**Schema Extension:**
- Purpose: Extend core SonicJS tables with app-specific columns
- Examples: `src/db/schema/user-profiles.ts` extends users table with profile fields
- Pattern: Drizzle sqliteTable with foreign key to core users table, Drizzle relations defined
- Type inference: TypeScript types auto-generated from schema ($inferSelect, $inferInsert)
- Relations: one-to-one relationship from userProfiles back to users

**Route Handler Pattern:**
- Purpose: Process HTTP requests for specific endpoints
- Examples: `src/plugins/contact-form/routes/public.ts`
- Pattern: Hono Router with method-specific handlers (get/post/put/patch/delete)
- Request handling: Get DB from context, instantiate service, call service methods, return response
- Response types: c.html() for HTML, c.json() for JSON, status codes (200/201/400/404/500)

## Entry Points

**Worker Entry Point:**
- Location: `src/index.ts`
- Triggers: Cloudflare Worker request event (any HTTP request to deployed worker)
- Responsibilities: Initialize collections, create SonicJS app, mount plugins, export default app

**Plugin Routes:**
- Location: `src/plugins/contact-form/routes/public.ts`, `routes/admin.ts`
- Triggers: HTTP requests matching plugin route paths (e.g., /contact, /api/contact)
- Responsibilities: Request parsing, validation, service invocation, response generation

**User Profile Routes:**
- Location: `src/routes/profile.ts`
- Triggers: GET/PUT/PATCH/DELETE /api/profile (with authentication)
- Responsibilities: CRUD operations for user profiles with dynamic schema filtering

**Database Migrations:**
- Location: `migrations/` (numbered SQL files)
- Triggers: Manual execution via `npm run db:migrate` command
- Responsibilities: Schema initialization, plugin table creation, content table setup

## Error Handling

**Strategy:** Try-catch with logging and error responses

**Patterns:**

- **Service Layer:** Try-catch wraps DB operations, console.error logs details, Error thrown with descriptive message
- **Route Handlers:** Try-catch wraps entire handler, returns JSON error response with status code (400/404/500), logs to console
- **Request Validation:** Manual null checks before database operations, returns 400 with validation error message
- **Plugin Operations:** Lifecycle hooks wrapped in try-catch, logs to console on error/success
- **External API Calls:** Cloudflare Turnstile verification wrapped, returns 400 if verification fails, 500 if service error
- **Database Constraints:** ON CONFLICT clauses in INSERT/UPDATE to handle duplicate keys, constraint violations caught in try-catch

## Cross-Cutting Concerns

**Logging:**
- Approach: console.error/log throughout codebase
- Timing: Service entry/exit points, DB operations, error conditions
- Format: Descriptive message strings, sometimes prefixed with [MethodName] for clarity
- Examples: `console.log('[ContactService.saveSettings] Starting save for plugin:', manifest.id)`

**Validation:**
- Approach: Schema-based (CollectionConfig) and manual validation
- Collections: JSON Schema in CollectionConfig validates required fields, types, maxLength
- API requests: Manual validation of required fields (name, email, msg) with early 400 returns
- Database: Drizzle schema enforces NOT NULL, UNIQUE, foreign key constraints
- Form input: HTML5 required attributes on client, server-side validation on POST

**Authentication:**
- Approach: Middleware-based auth via core SonicJS
- Implementation: requireAuth() middleware from @sonicjs-cms/core
- Admin routes: All contact form admin routes require authentication
- Public routes: Contact form public routes have requiresAuth: false
- User context: Authenticated user accessible via c.get('user') in handlers

**Database Access:**
- Approach: D1Database binding injection via Hono context
- Pattern: const db = c.get('db') || c.env?.DB in routes, passed to services
- ORM: Drizzle ORM for schema definition, D1 prepare/bind for SQL queries
- Transactions: No explicit transaction management visible (single operations)
- Connection pooling: Handled by Cloudflare D1 (automatic)

---

*Architecture analysis: 2026-01-30*
