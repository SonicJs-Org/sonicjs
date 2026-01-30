# Codebase Structure

**Analysis Date:** 2026-01-30

## Directory Layout

```
my-sonicjs-app/
├── src/                          # Application source code
│   ├── index.ts                  # Entry point: creates Hono app, registers collections, mounts plugins
│   ├── collections/              # Collection schema definitions
│   │   ├── blog-posts.collection.ts
│   │   ├── contact-messages.collection.ts
│   │   └── page-blocks.collection.ts
│   ├── db/                       # Database schema and ORM definitions
│   │   └── schema/
│   │       ├── index.ts
│   │       └── user-profiles.ts
│   ├── routes/                   # Custom API routes
│   │   └── profile.ts
│   └── plugins/                  # Custom plugins (extensible features)
│       ├── index.ts              # Plugin exports
│       └── contact-form/         # Contact form plugin module
│           ├── index.ts          # Plugin registration and builder
│           ├── types.ts          # TypeScript interfaces
│           ├── manifest.json
│           ├── services/
│           │   └── contact.ts    # ContactService with database logic
│           ├── routes/
│           │   ├── public.ts     # Public form routes
│           │   └── admin.ts      # Admin settings routes
│           ├── components/
│           │   └── settings-page.ts
│           └── test/
│               └── contact.spec.ts
├── migrations/                   # Database migration files (SQL)
│   ├── 001_initial_schema.sql
│   ├── 002_faq_plugin.sql
│   ├── ...
│   └── 031_contact_form_plugin.sql
├── scripts/                      # Utility and setup scripts
│   ├── seed-admin.ts
│   └── setup-worktree-db.sh
├── package.json
├── pnpm-lock.yaml
├── tsconfig.json
├── wrangler.toml                 # Cloudflare Workers configuration
├── README.md
└── .planning/                    # Planning documents (auto-generated)
    └── codebase/
        ├── ARCHITECTURE.md
        └── STRUCTURE.md
```

## Directory Purposes

**`src/`:**
- Purpose: All application code compiled from TypeScript
- Contains: Collections, routes, plugins, database schemas
- Key files: `index.ts` (app entry), all collection and plugin definitions

**`src/collections/`:**
- Purpose: Content type schemas (configuration-as-code)
- Contains: Collection definitions with name, display name, schema, UI config
- Key files:
  - `blog-posts.collection.ts`: Blog content type with title, slug, content, author, status, difficulty
  - `contact-messages.collection.ts`: Submitted contact form messages (name, email, message)
  - `page-blocks.collection.ts`: Flexible page builder with nested content blocks and team section

**`src/db/schema/`:**
- Purpose: Database table definitions using Drizzle ORM
- Contains: TypeScript definitions of custom database tables
- Key files:
  - `user-profiles.ts`: Extends core users table with profile fields (displayName, bio, company, jobTitle, website, location)
  - `index.ts`: Exports all schema definitions

**`src/routes/`:**
- Purpose: Custom HTTP endpoints beyond core CMS
- Contains: Hono route definitions with business logic
- Key files:
  - `profile.ts`: User profile CRUD API (GET, PUT, PATCH, DELETE /api/profile) with dynamic schema filtering

**`src/plugins/`:**
- Purpose: Modular features with routes, services, and settings
- Contains: Plugin-specific logic organized in subdirectories
- Key files:
  - `index.ts`: Plugin exports (currently minimal)
  - `contact-form/index.ts`: Plugin registration via PluginBuilder

**`src/plugins/contact-form/`:**
- Purpose: Complete plugin module for contact form feature
- Contains: Plugin definition, routes (public/admin), service layer, components, tests
- Key files:
  - `index.ts`: PluginBuilder with lifecycle hooks, routes, menu items, services
  - `types.ts`: ContactSettings, ContactMessage interfaces
  - `services/contact.ts`: ContactService (getSettings, saveMessage, saveMessages, lifecycle methods)
  - `routes/public.ts`: GET /contact (form page), POST /api/contact (submit form with Turnstile support)
  - `routes/admin.ts`: Admin routes for plugin management

**`migrations/`:**
- Purpose: Database schema versioning and evolution
- Contains: SQL migration files numbered 001-031
- Key files:
  - `001_initial_schema.sql`: Base schema (users, content, collections, plugins)
  - `031_contact_form_plugin.sql`: Latest migration for contact form table

**`scripts/`:**
- Purpose: Build-time and development utilities
- Contains: Seed data, database setup
- Key files:
  - `seed-admin.ts`: Creates initial admin user
  - `setup-worktree-db.sh`: Local development database initialization

## Key File Locations

**Entry Points:**
- `src/index.ts`: Application entry point for Wrangler worker

**Configuration:**
- `package.json`: NPM dependencies, scripts
- `tsconfig.json`: TypeScript compiler options
- `wrangler.toml`: Cloudflare Workers config (D1, R2, KV, environment)

**Core Logic:**
- `src/collections/`: All content type definitions (3 collections)
- `src/plugins/contact-form/services/contact.ts`: Plugin business logic (database operations)
- `src/routes/profile.ts`: Custom API route with Drizzle ORM

**Testing:**
- `src/plugins/contact-form/test/contact.spec.ts`: Contact form unit tests

## Naming Conventions

**Files:**
- Collections: `[name].collection.ts` (kebab-case name, .collection suffix)
  - Example: `blog-posts.collection.ts`, `contact-messages.collection.ts`
- Routes: `[name].ts` (kebab-case)
  - Example: `public.ts`, `admin.ts`, `profile.ts`
- Services: `[name].ts` (PascalCase class inside)
  - Example: `contact.ts` contains `class ContactService`
- Tests: `[name].spec.ts` or `[name].test.ts`
  - Example: `contact.spec.ts`
- Plugin directories: `[kebab-case-name]/`
  - Example: `contact-form/`

**Directories:**
- Plugins: `[kebab-case-name]/` containing `index.ts` and subdirectories
  - Example: `contact-form/`
- Schema layers: `schema/`, `services/`, `routes/`, `components/`, `test/`
- Core layers: `collections/`, `db/`, `routes/`, `plugins/`, `migrations/`, `scripts/`

**TypeScript:**
- Interfaces/Types: PascalCase (e.g., `ContactSettings`, `ContactMessage`, `ContactServiceResponse`)
- Classes: PascalCase (e.g., `ContactService`)
- Functions: camelCase (e.g., `createContactPlugin()`, `generateId()`)
- Variables: camelCase (e.g., `config`, `profileData`, `turnstileEnabled`)
- Constants: UPPER_SNAKE_CASE (not extensively used in current code)

## Where to Add New Code

**New Collection:**
1. Create file: `src/collections/[name].collection.ts`
2. Export default object satisfying `CollectionConfig` type
3. Import and register in `src/index.ts` via `registerCollections([...])`
4. Create migration: `migrations/NNN_add_[name]_collection.sql` if custom table needed

**New Plugin:**
1. Create directory: `src/plugins/[kebab-case-name]/`
2. Create `index.ts` using `PluginBuilder.create()` pattern
3. Create `manifest.json` with plugin metadata
4. Create `types.ts` for TypeScript interfaces
5. Create subdirectories as needed: `routes/`, `services/`, `components/`
6. Register in core app within `src/index.ts` if not auto-loaded
7. Add routes to plugin builder: `builder.addRoute(path, handler)`

**New Route:**
1. Create file: `src/routes/[name].ts` OR `src/plugins/[name]/routes/[purpose].ts`
2. Create Hono router: `const router = new Hono<{ Bindings, Variables }>()`
3. Implement handlers with proper auth/middleware
4. Mount in app via `app.route(path, router)` or plugin builder

**New Service:**
1. Create file: `src/plugins/[name]/services/[name].ts` OR `src/routes/[name].service.ts`
2. Create class with constructor taking `D1Database`
3. Implement async methods for database operations
4. Use prepared statements: `db.prepare(sql).bind(...).first()` or Drizzle ORM

**Utilities & Helpers:**
- Shared utilities: Not currently used in this app
- Plugin-specific utilities: Place in plugin directory alongside services
- Note: Core utilities are in `@sonicjs-cms/core` package

## Special Directories

**`migrations/`:**
- Purpose: Track database schema changes over time
- Generated: No (hand-written SQL)
- Committed: Yes (must be in version control)
- Naming: `NNN_description.sql` where NNN is sequential number
- Usage: Applied via `wrangler d1 migrations apply DB --local` or on deployment

**`node_modules/`:**
- Purpose: Installed dependencies
- Generated: Yes (by pnpm/npm)
- Committed: No (in .gitignore)

**`.wrangler/`:**
- Purpose: Wrangler local development database and build artifacts
- Generated: Yes (by Wrangler CLI)
- Committed: No (in .gitignore)

**`test-results/`:**
- Purpose: Test output and reports
- Generated: Yes (by test runner)
- Committed: No

**`.planning/codebase/`:**
- Purpose: GSD codebase analysis documents
- Generated: Yes (by GSD analysis tools)
- Committed: Yes (helpful for team reference)

---

*Structure analysis: 2026-01-30*
