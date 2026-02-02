# Codebase Structure

**Analysis Date:** 2026-02-01

## Directory Layout

```
sonicjs/
├── packages/                           # Published npm packages
│   ├── core/                          # @sonicjs-cms/core - Main framework package
│   │   ├── src/
│   │   │   ├── __tests__/             # Test suite
│   │   │   ├── app.ts                 # Application factory
│   │   │   ├── index.ts               # Public API exports
│   │   │   ├── db/                    # Database schema and migrations
│   │   │   ├── routes/                # HTTP route handlers
│   │   │   ├── services/              # Business logic services
│   │   │   ├── middleware/            # Cross-cutting concerns
│   │   │   ├── plugins/               # Plugin system and core plugins
│   │   │   ├── types/                 # TypeScript type definitions
│   │   │   ├── utils/                 # Shared utility functions
│   │   │   ├── templates/             # Server-side rendering templates
│   │   │   ├── schemas/               # Zod/JSON schemas
│   │   │   ├── collections/           # Example collection definitions
│   │   │   └── assets/                # Static assets (favicon, etc.)
│   │   ├── dist/                      # Compiled TypeScript output
│   │   ├── package.json               # Core package metadata and dependencies
│   │   └── vitest.config.ts           # Test configuration
│   ├── create-app/                    # create-sonicjs CLI template generator
│   │   ├── bin/                       # CLI entry point
│   │   ├── templates/                 # Project templates
│   │   └── src/
│   ├── stats/                         # Analytics and statistics package
│   └── templates/                     # Shared component templates
├── my-sonicjs-app/                    # Example SonicJS application
│   ├── src/
│   │   ├── index.ts                   # Application entry point
│   │   ├── collections/               # Custom collection configurations
│   │   ├── plugins/                   # Custom plugins
│   │   ├── routes/                    # Custom routes
│   │   └── db/                        # Database configuration
│   ├── migrations/                    # Database migrations
│   ├── wrangler.toml                  # Cloudflare Workers config
│   └── package.json
├── www/                               # Marketing website
│   ├── src/
│   │   ├── app/                       # Next.js app routes
│   │   ├── components/                # React components
│   │   ├── lib/                       # Utilities
│   │   └── styles/                    # CSS modules
│   └── content/
│       └── blog/                      # Blog post markdown
├── tests/                             # End-to-end tests
│   ├── e2e/                          # Playwright E2E tests
│   └── playwright*.config.ts          # Test configurations
├── scripts/                           # Build and utility scripts
│   ├── release/                       # Release automation
│   └── social/                        # Social media posting
├── docs/                              # Documentation
│   ├── architecture/                  # Architecture docs
│   ├── issues/                        # Issue tracking and solutions
│   ├── plugins/                       # Plugin documentation
│   ├── testing/                       # Testing guides
│   └── ai/                            # AI-related documentation
├── .planning/                         # GSD planning documents
│   ├── codebase/                      # Codebase analysis (ARCHITECTURE.md, STRUCTURE.md, etc.)
│   ├── phases/                        # Phase execution plans
│   └── milestones/                    # Project milestones
├── .github/
│   └── workflows/                     # GitHub Actions CI/CD
├── package.json                       # Monorepo root package
├── vitest.config.ts                   # Root test configuration
├── tsconfig.json                      # TypeScript configuration
└── README.md                          # Project documentation
```

## Directory Purposes

**`packages/core/src/`**
- Purpose: Main SonicJS framework implementation
- Contains: All core functionality for CMS operations, routing, plugins, authentication
- Key files: `app.ts` (app factory), `index.ts` (public API), `types/`, `services/`, `routes/`

**`packages/core/src/routes/`**
- Purpose: HTTP request handlers organized by feature area
- Contains: API routes, admin UI routes, auth routes, form routes
- Key files:
  - `api.ts`: API root with OpenAPI spec
  - `api-content-crud.ts`: Content CRUD operations
  - `api-media.ts`: Media upload and management
  - `api-system.ts`: System information endpoints
  - `auth.ts`: Login, logout, password reset flows
  - `admin-content.ts`: Content management UI
  - `admin-users.ts`: User administration
  - `admin-media.ts`: Media gallery admin
  - `admin-plugins.ts`: Plugin management
  - `admin-dashboard.ts`: Admin dashboard
  - `admin-collections.ts`: Collection management
  - `admin-settings.ts`: System settings UI
  - `public-forms.ts`: Form submission endpoints

**`packages/core/src/services/`**
- Purpose: Business logic layer for domain operations
- Contains: Collection management, authentication, caching, logging, migrations
- Key files:
  - `collection-loader.ts`: Discovers and validates collection configs
  - `collection-sync.ts`: Syncs schemas to database
  - `auth-validation.ts`: JWT and password verification
  - `migrations.ts`: Database migration runner
  - `plugin-bootstrap.ts`: Core plugin initialization
  - `plugin-service.ts`: Plugin lifecycle management
  - `logger.ts`: Centralized logging
  - `cache.ts`: Caching strategies
  - `telemetry-service.ts`: Usage tracking
  - `settings.ts`: System settings

**`packages/core/src/middleware/`**
- Purpose: Cross-cutting concerns (auth, logging, metrics, bootstrapping)
- Contains: Middleware functions for request processing
- Key files:
  - `bootstrap.ts`: One-time initialization (migrations, collection sync, plugins)
  - `auth.ts`: JWT and password utilities, auth enforcement
  - `metrics.ts`: Request timing
  - `plugin-middleware.ts`: Plugin-specific authorization

**`packages/core/src/plugins/`**
- Purpose: Plugin system and built-in plugins
- Contains: Hook system, plugin manager, registry, validator, and core plugins
- Key files:
  - `hook-system.ts`: Event-driven hook execution
  - `plugin-manager.ts`: Plugin lifecycle (install, activate, deactivate)
  - `plugin-registry.ts`: Plugin discovery and tracking
  - `plugin-validator.ts`: Plugin schema validation
  - `core-plugins/`: Built-in plugins (email, OTP login, AI search, database tools)
  - `available/`: Optional plugins (magic link auth, cache)
  - `sdk/`: Plugin builder and utilities

**`packages/core/src/types/`**
- Purpose: TypeScript type definitions
- Contains: Plugin interface, collection config types, manifest types
- Key files:
  - `plugin.ts`: Plugin, PluginContext, PluginHook, HookSystem interfaces
  - `collection-config.ts`: CollectionConfig, FieldConfig, FieldType types
  - `plugin-manifest.ts`: Plugin metadata structure
  - `telemetry.ts`: Event and telemetry types
  - `global.d.ts`: Cloudflare Workers global types

**`packages/core/src/db/`**
- Purpose: Database schema and initialization
- Contains: Drizzle ORM tables, migrations, database setup
- Key files:
  - `schema.ts`: Table definitions (users, collections, content, media, plugins, logs)
  - `migrations/`: SQL migrations and bundled migration runner
  - `index.ts`: Database initialization function

**`packages/core/src/utils/`**
- Purpose: Shared utility functions
- Contains: Helpers for common operations across codebase
- Key files:
  - `query-filter.ts`: Query builder for filtering and pagination
  - `sanitize.ts`: HTML escaping and input validation
  - `template-renderer.ts`: Server-side template rendering
  - `metrics.ts`: Metrics tracking
  - `telemetry-*.ts`: Telemetry configuration and ID generation

**`packages/core/src/templates/`**
- Purpose: Server-side template rendering for admin UI components
- Contains: HTML rendering functions for forms, tables, alerts, etc.
- Key files: `form.ts`, `table.ts`, `pagination.ts`, `alert.ts`

**`packages/core/src/collections/`**
- Purpose: Example collection definitions for core package
- Contains: Reference collection implementations
- Key files: `test-items.collection.ts` (test data collection)

**`my-sonicjs-app/`**
- Purpose: Example SonicJS application
- Contains: Collection definitions, custom plugins, custom routes
- Key files:
  - `src/index.ts`: App entry point - registers collections and mounts plugins
  - `src/collections/`: Custom collection definitions (blog posts, page blocks)
  - `src/plugins/`: Custom plugins (contact form, redirect management)

**`my-sonicjs-app/src/collections/`**
- Purpose: User-defined content models
- Contains: Collection configuration files
- Key files:
  - `blog-posts.collection.ts`: Blog post collection with rich editor, categories, tags
  - `page-blocks.collection.ts`: Reusable content blocks for page composition
  - `contact-messages.collection.ts`: Contact form submissions storage

**`my-sonicjs-app/src/plugins/`**
- Purpose: Custom plugins extending core functionality
- Contains: Plugin implementations with routes, middleware, services
- Key files:
  - `contact-form/`: Form builder and submission handler
  - `redirect-management/`: 301/302 redirect rules with admin UI

**`tests/`**
- Purpose: End-to-end test suite
- Contains: Playwright test scenarios
- Key files:
  - `e2e/`: Test scenarios for core functionality
  - `playwright.config.ts`: Full test suite config
  - `playwright.smoke.config.ts`: Quick smoke tests

**`docs/`**
- Purpose: Project documentation
- Contains: Architecture guides, plugin docs, testing guides
- Key files: Architecture guides, API reference, plugin development guide

**`.planning/codebase/`**
- Purpose: GSD codebase analysis documents
- Contains: Architecture analysis, structure mapping, conventions, testing patterns, concerns
- Key files: `ARCHITECTURE.md`, `STRUCTURE.md`, `CONVENTIONS.md`, `TESTING.md`, `CONCERNS.md`

## Key File Locations

**Entry Points:**
- `packages/core/src/index.ts`: Core package public API exports
- `packages/core/src/app.ts`: Application factory function `createSonicJSApp()`
- `my-sonicjs-app/src/index.ts`: Example application entry point
- `packages/core/src/middleware/bootstrap.ts`: System initialization

**Configuration:**
- `packages/core/package.json`: Core package dependencies and build config
- `my-sonicjs-app/wrangler.toml`: Cloudflare Workers deployment config
- `my-sonicjs-app/src/index.ts`: Application-level configuration (collections, plugins)
- `tsconfig.json`: TypeScript compiler configuration
- `vitest.config.ts`: Test runner configuration

**Core Logic:**
- `packages/core/src/services/`: All business logic services
- `packages/core/src/plugins/hook-system.ts`: Event-driven extensibility
- `packages/core/src/plugins/plugin-manager.ts`: Plugin lifecycle management
- `packages/core/src/db/schema.ts`: Database tables and relationships
- `packages/core/src/middleware/auth.ts`: JWT and authentication

**Testing:**
- `packages/core/src/__tests__/`: Core package test suite
- `tests/e2e/`: End-to-end tests
- `vitest.config.ts`: Root test configuration
- Individual `*.test.ts` files alongside source code

## Naming Conventions

**Files:**
- Feature files: `kebab-case.ts` (e.g., `collection-loader.ts`, `plugin-manager.ts`)
- Test files: `*.test.ts` (e.g., `collection-sync.test.ts`)
- Collection configs: `*.collection.ts` (e.g., `blog-posts.collection.ts`)
- Route files: `route-name.ts` (e.g., `admin-content.ts`, `api-media.ts`)
- Types: `type-name.ts` (e.g., `plugin.ts`, `collection-config.ts`)

**Directories:**
- Feature directories: `kebab-case/` (e.g., `core-plugins/`, `services/`, `middleware/`)
- Collection directory: `collections/`
- Plugin directory: `plugins/`
- Route directory: `routes/`
- Test directory: `__tests__/`

**TypeScript:**
- Types/Interfaces: PascalCase (e.g., `Plugin`, `CollectionConfig`, `HookSystem`)
- Functions: camelCase (e.g., `createSonicJSApp`, `loadCollectionConfigs`)
- Classes: PascalCase (e.g., `AuthManager`, `PluginManager`)
- Constants: UPPER_SNAKE_CASE (e.g., `HOOKS`, `ROUTES_INFO`)
- Private members: `_leadingUnderscore` (e.g., `_hooks`, `_executing`)

## Where to Add New Code

**New Feature (API endpoint/route):**
- API logic: `packages/core/src/services/[feature-name].ts`
- Route handler: `packages/core/src/routes/[feature-name].ts`
- Tests: `packages/core/src/__tests__/[feature-name].test.ts`
- Types: Add to `packages/core/src/types/[feature-name].ts` or existing type file
- Database: Add table to `packages/core/src/db/schema.ts` and migration to `packages/core/src/db/migrations/`

**New Collection:**
- Collection config: `my-sonicjs-app/src/collections/[name].collection.ts`
- Register in: `my-sonicjs-app/src/index.ts` via `registerCollections([...])`

**New Plugin:**
- Plugin directory: `my-sonicjs-app/src/plugins/[plugin-name]/`
- Plugin file: `my-sonicjs-app/src/plugins/[plugin-name]/index.ts`
- Admin routes (if any): `my-sonicjs-app/src/plugins/[plugin-name]/admin-routes.ts`
- Services (if any): `my-sonicjs-app/src/plugins/[plugin-name]/services/`
- Mount in: `my-sonicjs-app/src/index.ts` via `app.route(route.path, route.handler)`

**Middleware/Utilities:**
- Cross-cutting middleware: `packages/core/src/middleware/[concern].ts`
- Utilities: `packages/core/src/utils/[utility-name].ts`
- Both should be exported from `packages/core/src/index.ts`

**Tests:**
- Unit tests: Co-locate with source as `*.test.ts`
- E2E tests: `tests/e2e/[feature].spec.ts`
- Test utilities: `tests/e2e/utils/`

## Special Directories

**`packages/core/src/__tests__/`**
- Purpose: Vitest test suite for core package
- Generated: No (hand-written)
- Committed: Yes (all tests committed)
- Contents: Unit tests for services, middleware, utilities, plugins

**`packages/core/src/plugins/core-plugins/`**
- Purpose: Built-in plugins that ship with core package
- Generated: No (hand-written)
- Committed: Yes
- Examples: email-plugin, otp-login-plugin, ai-search-plugin, database-tools-plugin, seed-data-plugin

**`packages/core/dist/`**
- Purpose: Compiled JavaScript output
- Generated: Yes (from `npm run build`)
- Committed: No (gitignored)

**`my-sonicjs-app/.wrangler/`**
- Purpose: Cloudflare Workers local development state
- Generated: Yes (by wrangler CLI)
- Committed: No (gitignored)

**`my-sonicjs-app/migrations/`**
- Purpose: Application-specific database migrations
- Generated: No (hand-written)
- Committed: Yes

**`.planning/codebase/`**
- Purpose: GSD-generated codebase analysis documents
- Generated: Yes (by map-codebase tool)
- Committed: Yes (reference documents for planning)

**`node_modules/`**
- Purpose: Installed npm dependencies
- Generated: Yes (by npm install)
- Committed: No (gitignored)

---

*Structure analysis: 2026-02-01*
