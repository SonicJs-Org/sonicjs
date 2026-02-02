# Architecture

**Analysis Date:** 2026-02-01

## Pattern Overview

**Overall:** Layered Architecture with Edge-Native Design

SonicJS is a headless CMS built as a modular TypeScript application targeting Cloudflare Workers. The architecture follows a layered approach with separation between core framework functionality (`@sonicjs-cms/core` package), application-specific implementations (collections, plugins, routes), and edge runtime constraints.

**Key Characteristics:**
- **Edge-Native**: Built for Cloudflare Workers with D1 database, R2 storage, and KV caching
- **Plugin-Driven Extensibility**: Core hook system and plugin manager enable runtime feature extension without modifying core code
- **Configuration-as-Code**: Collections, plugins, and middleware are configured via TypeScript modules
- **Request-Scoped Context**: Hono's context binding carries authentication, user data, and request metadata through entire request lifecycle
- **Single-Pass Bootstrap**: Migrations, collection syncing, and plugin initialization run once per worker instance

## Layers

**Presentation Layer (Routes):**
- Purpose: Handle HTTP request/response lifecycle, route matching, and view rendering
- Location: `packages/core/src/routes/` and `my-sonicjs-app/src/routes/`
- Contains: Hono route handlers for API endpoints, admin UI routes, auth routes, and custom routes
- Depends on: Services, middleware, middleware utilities, templates, types
- Used by: Hono framework for request routing

**Application/Business Logic Layer (Services):**
- Purpose: Core business logic including collection management, authentication, media handling, logging, migrations, caching, and plugin initialization
- Location: `packages/core/src/services/`
- Contains:
  - `collection-loader.ts`: Loads and registers collection configurations from code and core package
  - `collection-sync.ts`: Syncs collection schemas to database, manages collection lifecycle
  - `auth-validation.ts`: Validates JWT tokens, password verification, user authentication flows
  - `cache.ts`: Cache service for plugin caching strategies
  - `migrations.ts`: Database migration execution and tracking
  - `plugin-bootstrap.ts`: Core plugin initialization and bootstrap
  - `plugin-service.ts`: Plugin lifecycle management and status tracking
  - `logger.ts`: Centralized logging with multiple handlers
  - `telemetry-service.ts`: Anonymized usage tracking and telemetry
  - `settings.ts`: System settings persistence and retrieval
- Depends on: Database, types, utilities, plugins
- Used by: Routes, middleware, plugins

**Middleware Layer:**
- Purpose: Cross-cutting concerns including authentication, metrics, bootstrap, and plugin authorization
- Location: `packages/core/src/middleware/`
- Contains:
  - `bootstrap.ts`: One-time system initialization (migrations, collection sync, plugin bootstrap)
  - `auth.ts`: JWT generation/verification, password hashing, authentication enforcement
  - `metrics.ts`: Request timing and metrics tracking
  - `plugin-middleware.ts`: Plugin-specific authentication and authorization checks
  - `admin-setup.ts`: Initial admin user creation
- Depends on: Services, utilities, types
- Used by: App factory function and route handlers

**Plugin System:**
- Purpose: Runtime extensibility framework for custom functionality without modifying core
- Location: `packages/core/src/plugins/`
- Contains:
  - `hook-system.ts`: Event-driven hook registration and execution with priority ordering
  - `plugin-manager.ts`: Plugin lifecycle management (install, activate, deactivate)
  - `plugin-registry.ts`: Plugin discovery and registration tracking
  - `plugin-validator.ts`: Plugin validation against schema constraints
  - `core-plugins/`: Built-in plugins (email, OTP login, AI search, database tools, seed data)
  - `available/`: Optional plugins (magic link auth, cache management)
  - `sdk/`: Plugin builder utilities for creating custom plugins
- Depends on: Types, database, services
- Used by: App factory, bootstrap middleware, routes

**Data Access Layer (Database & Schema):**
- Purpose: Database schema definitions, connection management, type-safe query building
- Location: `packages/core/src/db/`
- Contains:
  - `schema.ts`: Drizzle ORM schema definitions for users, collections, content, media, plugins, workflows, logs
  - `migrations/`: Database migrations and bundled migration runner
  - `index.ts`: Database initialization and instance creation
- Depends on: Drizzle ORM, Zod validation
- Used by: Services, routes

**Type System:**
- Purpose: TypeScript type definitions for strong typing throughout codebase
- Location: `packages/core/src/types/`
- Contains:
  - `plugin.ts`: Plugin interface, context, hooks, validation
  - `collection-config.ts`: Collection schema and configuration types
  - `plugin-manifest.ts`: Plugin metadata and manifest types
  - `telemetry.ts`: Telemetry event type definitions
  - `global.d.ts`: Global type definitions for Cloudflare Workers
- Depends on: Hono types, Cloudflare Workers types
- Used by: All layers

**Utilities Layer:**
- Purpose: Shared helper functions for common operations
- Location: `packages/core/src/utils/`
- Contains:
  - `query-filter.ts`: Query builder for filtering, sorting, pagination
  - `sanitize.ts`: HTML escaping and input sanitization
  - `template-renderer.ts`: Server-side template rendering
  - `metrics.ts`: Metrics tracking utilities
  - `telemetry-*.ts`: Telemetry ID and configuration helpers
  - `version.ts`: Version retrieval
- Depends on: Types
- Used by: All layers

**Configuration & Collections:**
- Purpose: User-defined data models and application configuration
- Location: `my-sonicjs-app/src/collections/` and `my-sonicjs-app/src/plugins/`
- Contains: Collection definitions (blog-posts, page-blocks, contact-messages), custom plugins
- Depends on: Core types and services
- Used by: Core services and routes

## Data Flow

**Request Initialization:**

1. HTTP request arrives at Hono application
2. Hono routes request through registered middleware stack:
   - App version middleware (sets version in context)
   - Metrics middleware (starts request timer)
   - Bootstrap middleware (one-time initialization)
   - Custom beforeAuth middleware
   - Auth middleware (JWT verification if required)
   - Custom afterAuth middleware
3. Route handler executes and uses `c.env` (Bindings) and `c.var` (Variables) for data access
4. Response is returned with timing headers

**Collection Sync Flow:**

1. Bootstrap middleware triggers `syncCollections(db)`
2. `loadCollectionConfigs()` gathers all collection definitions (registered + core)
3. For each collection:
   - Schema is validated against JSON schema
   - Collection record is created or updated in `collections` table if new
   - Dynamic table for collection content is created if needed
   - Schema changes are applied
   - Associated indexes are created
4. Removed collections are cleaned up if applicable

**Authentication Flow:**

1. User submits login credentials via `/auth` route
2. `AuthManager.verifyPassword()` checks credentials
3. `AuthManager.generateToken()` creates JWT with userId, email, role
4. Token is set in httpOnly cookie and/or returned in response
5. Subsequent requests carry token in Authorization header or cookie
6. `requireAuth` middleware verifies token and populates `c.var.user`
7. Routes access user info via `c.var.user`

**Plugin Execution Flow:**

1. Bootstrap middleware calls `PluginBootstrapService.bootstrapCorePlugins()`
2. Core plugins are registered in database if not already present
3. `PluginManager` loads plugin instances and calls `activate()` lifecycle hook
4. Plugins register routes via route handler mounting in app factory
5. Plugins register middleware via middleware stacks
6. Hooks are registered for specific events
7. During request, hooks are executed at defined points (e.g., before content creation)

**Hook Execution:**

1. Code calls `hookSystem.execute('hook-name', data, context)`
2. Hook system retrieves all registered handlers for hook name
3. Handlers are sorted by priority (lower = earlier execution)
4. Each handler is executed sequentially with result chaining
5. If handler throws CRITICAL error, execution stops and error propagates
6. Otherwise, execution continues to next handler
7. Final result is returned to caller

**State Management:**

- **Request Scoping**: Hono's context (`c`) carries request-scoped state (user, requestId, metrics)
- **Persistent State**: Database stores collections, content, users, media, plugins, logs
- **Caching**: KV namespace used for temporary caching of plugin results and frequently accessed data
- **Worker Instance**: Bootstrap flag (`bootstrapComplete`) ensures one-time initialization per worker instance
- **Collections Registry**: Global `registeredCollections` array holds in-memory collection configs

## Key Abstractions

**Plugin System:**
- Purpose: Runtime extensibility for custom features (email, OTP, search, forms, etc.)
- Examples: `packages/core/src/plugins/core-plugins/email-plugin`, `my-sonicjs-app/src/plugins/contact-form`
- Pattern: Plugin implements `Plugin` interface with optional routes, middleware, hooks, lifecycle methods. Core registers via PluginManager.

**Collection Configuration:**
- Purpose: Define content schema as code, auto-sync to database
- Examples: `my-sonicjs-app/src/collections/blog-posts.collection.ts`
- Pattern: TypeScript module exports `CollectionConfig` satisfying type contract. Loader discovers and validates at startup.

**Hook System:**
- Purpose: Event-driven inter-plugin communication
- Examples: `before:content:create`, `after:content:publish`, `before:auth:login`
- Pattern: Plugins register handlers via `hookSystem.register(hookName, handler, priority)`. Core executes handlers sequentially by priority.

**Route Registry:**
- Purpose: Mount custom routes without modifying core router
- Examples: Plugin routes mounted in app factory (`app.route(route.path, route.handler)`)
- Pattern: Plugins export route array. Core or application code mounts routes at startup.

**Context Binding:**
- Purpose: Pass request-scoped data (user, metrics, bindings) through entire call stack without parameter drilling
- Examples: `c.var.user`, `c.env.DB`, `c.set('startTime', Date.now())`
- Pattern: Hono's `Context<{ Bindings: Bindings; Variables: Variables }>` carries type-safe state.

## Entry Points

**Core Package Export:**
- Location: `packages/core/src/index.ts`
- Triggers: `npm install @sonicjs-cms/core` in application
- Responsibilities: Exports all public APIs (app factory, services, middleware, types, utilities)

**Application Entry:**
- Location: `my-sonicjs-app/src/index.ts`
- Triggers: `npm run dev` or deployment
- Responsibilities:
  1. Import and register custom collections
  2. Import and configure custom plugins
  3. Create core app with `createSonicJSApp(config)`
  4. Mount plugin routes and middleware
  5. Mount core app as fallback route
  6. Export Hono app instance

**App Factory:**
- Location: `packages/core/src/app.ts` (`createSonicJSApp` function)
- Triggers: Called during application initialization
- Responsibilities:
  1. Create Hono instance with Bindings and Variables types
  2. Mount app-level middleware (version, metrics, bootstrap, security)
  3. Register all core routes (API, admin, auth, forms)
  4. Register plugin routes (AI search, OTP login, cache, email, magic link)
  5. Set up favicon and static file serving
  6. Return configured Hono app

**Bootstrap Middleware:**
- Location: `packages/core/src/middleware/bootstrap.ts`
- Triggers: First HTTP request to application
- Responsibilities:
  1. Run pending database migrations via `MigrationService`
  2. Sync collection configurations via `syncCollections()`
  3. Bootstrap core plugins via `PluginBootstrapService`
  4. Set `bootstrapComplete` flag to prevent re-execution

## Error Handling

**Strategy:** Errors are logged and propagated to caller; non-critical errors don't block request

**Patterns:**
- **Collection Sync Errors**: Logged and continue bootstrap (allows app to start even if sync fails)
- **Hook Execution Errors**: Logged unless marked CRITICAL; subsequent hooks still execute
- **Plugin Bootstrap Errors**: Logged; specific plugins may fail to initialize but others continue
- **Auth Errors**: Return 401 Unauthorized response
- **Validation Errors**: Return 400 Bad Request with error details
- **Database Errors**: Logged and return 500 Internal Server Error

## Cross-Cutting Concerns

**Logging:**
- Approach: Centralized `Logger` service (`packages/core/src/services/logger.ts`) with handlers for console, systemLogs table
- Usage: Services and routes call `getLogger(category)` to get logger instance
- Categories: 'auth', 'collection', 'plugin', 'system', 'error'

**Validation:**
- Approach: Zod schemas for database entities, JSON schema for collection configurations
- Location: Database schemas (`packages/core/src/db/schema.ts`), collection types (`packages/core/src/types/collection-config.ts`)
- Enforcement: Collection schemas validated during sync; request data validated in routes via `@hono/zod-validator`

**Authentication:**
- Approach: JWT tokens generated by `AuthManager` on login, verified in `requireAuth` middleware
- Token Structure: `{ userId, email, role, exp, iat }`
- Storage: httpOnly secure cookie + Authorization header support
- Verification: Checked on protected routes via `requireAuth` or `optionalAuth` middleware

---

*Architecture analysis: 2026-02-01*
