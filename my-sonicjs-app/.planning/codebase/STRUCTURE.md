# Codebase Structure

**Analysis Date:** 2026-01-30

## Directory Layout

```
my-sonicjs-app/
├── src/                          # Application source code
│   ├── index.ts                  # Worker entry point, app initialization
│   ├── collections/              # Content type definitions
│   ├── db/                        # Database schema extensions
│   ├── plugins/                   # Custom plugin implementations
│   └── routes/                    # Additional route handlers
├── migrations/                    # SQL migration files for database schema
├── scripts/                       # Build and setup scripts
├── .planning/                     # GSD planning documents (this directory)
├── .wrangler/                     # Wrangler development state (generated)
├── wrangler.toml                  # Cloudflare Workers configuration
├── tsconfig.json                  # TypeScript compiler configuration
├── package.json                   # Node.js dependencies and scripts
└── vitest.config.ts               # Test runner configuration (if present)
```

## Directory Purposes

**src:**
- Purpose: All application source code
- Contains: TypeScript files for routes, collections, plugins, database schemas
- Key files: `index.ts` (entry point), `collections/*.ts` (content definitions)

**src/collections:**
- Purpose: Content type definitions as configuration
- Contains: CollectionConfig objects defining schemas, fields, admin UI settings
- Key files:
  - `blog-posts.collection.ts`: Blog post content type with rich editor, featured image, publish workflow
  - `contact-messages.collection.ts`: Auto-populated by contact form plugin, stores submitted messages
  - `page-blocks.collection.ts`: Pages with flexible content blocks (text, images, CTA, team sections)

**src/db:**
- Purpose: Database schema extensions specific to this application
- Contains: Drizzle ORM table definitions that extend core SonicJS schema
- Key files: `schema/index.ts` (barrel export), `schema/user-profiles.ts` (extended user data)

**src/db/schema:**
- Purpose: Application-specific database table definitions
- Contains: Drizzle sqliteTable definitions with relations and TypeScript types
- Customization: Add new tables here for app-specific entities (profiles, preferences, etc.)

**src/plugins:**
- Purpose: Custom plugin implementations extending core CMS features
- Contains: Self-contained plugin packages with routes, services, components
- Key plugins:
  - `contact-form/`: Full-featured contact form with Google Maps, Turnstile, settings management

**src/plugins/contact-form:**
- Purpose: Contact form feature plugin
- Structure:
  - `index.ts`: Plugin definition using PluginBuilder API
  - `manifest.json`: Plugin metadata (id, version, author, description)
  - `types.ts`: TypeScript interfaces for ContactSettings and ContactMessage
  - `routes/`: HTTP endpoint handlers (public.ts, admin.ts)
  - `services/`: Business logic (ContactService for form operations)
  - `components/`: UI components (settings-page.ts for admin interface)
  - `test/`: Test files (contact.spec.ts using Playwright)
  - `migrations/`: SQL migrations for plugin tables (if any)

**src/plugins/index.ts:**
- Purpose: Barrel export of all custom plugins
- Contains: Re-exports for plugin discovery and initialization
- Pattern: `export { default as contactFormPlugin } from './contact-form/index'`

**src/routes:**
- Purpose: Application-level route handlers not part of plugins
- Contains: Additional API routes and page routes
- Key files: `profile.ts` (user profile CRUD API with authentication)

**migrations:**
- Purpose: SQL database schema initialization and updates
- Contains: Numbered .sql files that execute in order during database setup
- Pattern: 001_initial_schema.sql, 002_faq_plugin.sql, etc.
- Execution: Via `wrangler d1 migrations apply DB` command
- Key migrations:
  - `001_initial_schema.sql`: Core tables (content, collections, users, plugins)
  - `018_user_profiles.sql`: user_profiles table extension
  - `031_contact_form_plugin.sql`: Contact form plugin database setup

**scripts:**
- Purpose: Setup and utility scripts
- Contains: Bash scripts, TypeScript build scripts
- Key files: `seed-admin.ts` (creates initial admin user), `setup-worktree-db.sh` (DB setup)

## Key File Locations

**Entry Points:**
- `src/index.ts`: Cloudflare Worker entry point - loads collections, creates core app, mounts plugins

**Configuration:**
- `wrangler.toml`: Cloudflare Workers deployment config (account, D1 database, R2 bucket, KV cache bindings)
- `tsconfig.json`: TypeScript compiler settings (strict mode, ES2022 target, path aliases)
- `package.json`: Dependencies (Hono, Drizzle, Zod, Wrangler), scripts (dev, test, db commands)

**Core Logic:**
- `src/plugins/contact-form/services/contact.ts`: ContactService class - handles form submission, settings persistence
- `src/plugins/contact-form/routes/public.ts`: Public form page and submission endpoint (/contact, /api/contact)
- `src/plugins/contact-form/routes/admin.ts`: Admin settings page for contact form configuration

**Database Schema:**
- `src/db/schema/user-profiles.ts`: User profile extension with displayName, bio, company, location, etc.
- `migrations/031_contact_form_plugin.sql`: Contact form database initialization

**Tests:**
- `src/plugins/contact-form/test/contact.spec.ts`: E2E tests using Playwright (form submission, settings toggle)

## Naming Conventions

**Files:**
- Collections: `{entity-name}.collection.ts` (kebab-case entity, .collection suffix)
  - Examples: `blog-posts.collection.ts`, `contact-messages.collection.ts`
- Services: `{entity-name}.ts` (simple entity name in PascalCase class)
  - Examples: `contact.ts` exports ContactService class
- Routes: `{type}.ts` where type is public, admin, api
  - Examples: `public.ts`, `admin.ts`
- Database schemas: `{table-name}.ts` (kebab-case or camelCase matching table name)
  - Examples: `user-profiles.ts`
- Migrations: `{number}_{description}.sql` (zero-padded number, snake_case description)
  - Examples: `001_initial_schema.sql`, `031_contact_form_plugin.sql`
- Plugins: Directory name in kebab-case (`contact-form`), main file is `index.ts`

**Directories:**
- Collections: `collections/` (plural)
- Database schema: `db/schema/` (nested structure)
- Plugins: `plugins/{plugin-name}/` (kebab-case plugin name)
- Routes: `routes/` or `routes/{type}/` (organized by access level)
- Tests: `test/` or `__tests__/` within module (adjacent to code)
- Scripts: `scripts/` (root level)

**Database Tables:**
- Collections table: `collections` (stores content type definitions)
- Content table: `content` (stores actual content items with collection_id)
- Users table: `users` (core authentication and user management)
- Plugins table: `plugins` (plugin metadata and settings as JSON)
- User profiles table: `user_profiles` (extended user data)

**Class Names:**
- Service classes: PascalCase with Service suffix (ContactService)
- Plugin ID: kebab-case (contact-form, email)

## Where to Add New Code

**New Feature (e.g., FAQ Plugin):**
- Primary code: `src/plugins/{feature-name}/` directory structure
  - `index.ts`: Plugin definition with PluginBuilder
  - `routes/public.ts`: Public-facing endpoints
  - `routes/admin.ts`: Admin panel endpoints
  - `services/{feature-name}.ts`: Business logic class
  - `types.ts`: TypeScript interfaces
  - `manifest.json`: Plugin metadata
- Tests: `src/plugins/{feature-name}/test/*.spec.ts`
- Database: `src/plugins/{feature-name}/migrations/*.sql`
- Export: Add to `src/plugins/index.ts` barrel export
- Register in: `src/index.ts` config.plugins.enabled array and manual route mounting

**New Component/Module:**
- Implementation: `src/routes/{module-name}.ts` for route handlers
- Or: `src/plugins/{parent-plugin}/components/{component-name}.ts` for plugin sub-components
- Database schema: `src/db/schema/{table-name}.ts` (Drizzle ORM definition)
- Export schema: In `src/db/schema/index.ts` barrel export

**New Collection Type:**
- File: `src/collections/{entity-name}.collection.ts`
- Pattern: Export satisfies CollectionConfig
- Register: Add import and include in `registerCollections([...])` in `src/index.ts`
- Example pattern from `blog-posts.collection.ts`:
  ```typescript
  export default {
    name: "entity_name",        // snake_case, matches DB table
    displayName: "Display Name",
    icon: "emoji",
    schema: {
      type: "object",
      properties: { /* field definitions */ },
      required: [/* field names */]
    },
    listFields: [/* admin list view columns */],
    searchFields: [/* full-text search fields */],
    managed: true,
    isActive: true
  } satisfies CollectionConfig
  ```

**Utilities and Helpers:**
- Shared helpers: `src/utils/` directory (create if needed)
- Service utilities: Methods within service class
- Route utilities: Helper functions in route file or separate utils file
- Type utilities: In `src/db/schema/index.ts` or service types.ts file

## Special Directories

**migrations/:**
- Purpose: Track database schema changes over time
- Generated: Manually created, not auto-generated
- Committed: Yes, version controlled for reproducible deployments
- Execution: Manual via `npm run db:migrate` (development) or GitHub Actions (production)
- Order: Numbered sequentially, applied in order
- Example content: CREATE TABLE, ALTER TABLE, INSERT default data

**.wrangler/:**
- Purpose: Wrangler development runtime state
- Generated: Yes, automatically by Wrangler CLI during dev/build
- Committed: No, in .gitignore
- Contents: Local worker state, D1 database files, temporary files

**.planning/:**
- Purpose: GSD planning documents and analysis
- Generated: Created by GSD commands (/gsd:map-codebase, /gsd:plan-phase, etc.)
- Committed: Yes, documents are version controlled
- Subdir: `codebase/` contains architecture/structure/conventions docs

## Module Organization Pattern

**Plugin Module (contact-form as example):**

```
src/plugins/contact-form/
├── index.ts                    # Plugin definition
├── manifest.json              # Metadata
├── types.ts                   # TS interfaces
├── routes/
│   ├── public.ts              # User-facing routes (no auth)
│   └── admin.ts               # Admin routes (requiresAuth)
├── services/
│   └── contact.ts             # Business logic class
├── components/
│   └── settings-page.ts       # UI components (Web Components or HTML generation)
├── test/
│   └── contact.spec.ts        # E2E tests
└── migrations/
    └── 031_contact_form_plugin.sql
```

**Route Handler Pattern (from `src/routes/profile.ts`):**

```typescript
// 1. Imports
import { Hono } from 'hono'
import { drizzle } from 'drizzle-orm/d1'
import { requireAuth } from '@sonicjs-cms/core'

// 2. Create router
const router = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// 3. Apply middleware
router.use('*', requireAuth())

// 4. Define handlers
router.get('/', async (c) => {
  const user = c.get('user')
  const db = drizzle(c.env.DB)
  // ... implementation
  return c.json(result)
})

// 5. Export
export default router as unknown as Hono
```

**Collection Definition Pattern (from `blog-posts.collection.ts`):**

```typescript
import type { CollectionConfig } from "@sonicjs-cms/core"

export default {
  name: "blog_posts",            // Matches DB collection name
  displayName: "Blog Posts",
  schema: {
    type: "object",
    properties: {
      title: { type: "string", required: true },
      slug: { type: "slug", required: true },
      content: { type: "quill", required: true }
    },
    required: ["title", "slug", "content"]
  },
  listFields: ["title", "author", "status"],
  searchFields: ["title", "content"],
  managed: true,
  isActive: true
} satisfies CollectionConfig
```

**Service Class Pattern (from `contact.ts`):**

```typescript
import type { D1Database } from '@cloudflare/workers-types'

export class ContactService {
  constructor(private db: D1Database) {}

  async getSettings() {
    try {
      const record = await this.db
        .prepare(`SELECT settings FROM plugins WHERE id = ?`)
        .bind('contact-form')
        .first()
      return { status: 'active', data: record.settings }
    } catch (error) {
      console.error('Error:', error)
      throw error
    }
  }

  async saveMessage(data: ContactMessage) {
    // ... implementation
  }
}
```

---

*Structure analysis: 2026-01-30*
