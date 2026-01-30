# Phase 1: Foundation & Plugin Structure - Research

**Researched:** 2026-01-30
**Domain:** SonicJS plugin development with D1 database and collection schema
**Confidence:** HIGH

## Summary

This research investigated how to build a SonicJS plugin with proper infrastructure: plugin registration using PluginBuilder, collection schema definition for D1 database storage, and database migrations. The investigation focused on the SonicJS plugin architecture, D1/SQLite migration patterns, and the contact-form plugin as the architectural reference.

SonicJS plugins use a fluent PluginBuilder API that registers lifecycle hooks, routes, services, and admin interface components. Database schemas are defined in SQL migrations that create tables and seed data, with collections stored in the core `collections` table (schema as JSON) and actual content in the `content` table (data as JSON). The migration system uses sequential numbered SQL files executed via MigrationService.

The standard approach follows the contact-form plugin pattern: create plugin with PluginBuilder, define lifecycle methods (install/activate/deactivate/uninstall) in a service class, write SQL migration to insert plugin metadata and create necessary tables/indexes, and export the built plugin as default. For collection-based plugins, the migration creates a collection entry in the `collections` table with schema definition, and the plugin service manages data via the `content` table.

**Primary recommendation:** Use PluginBuilder fluent API for plugin structure, create a dedicated service class for lifecycle and business logic, write a single SQL migration file for plugin registration and schema setup, and follow the contact-form plugin's folder structure and patterns.

## Standard Stack

The established libraries/tools for this domain:

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| @sonicjs-cms/core | 2.x | SonicJS plugin SDK | Provides PluginBuilder, type definitions, and plugin manager integration |
| TypeScript | ^5.8.3 | Type safety | Required for SonicJS development, provides compile-time type checking |
| Drizzle ORM | ^0.44.2 | Database operations (optional) | Type-safe database queries, though SonicJS uses raw D1 SQL in migrations |
| Cloudflare D1 | N/A | SQLite database | SonicJS's database layer, serverless SQLite on Cloudflare edge |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| Zod | ^3.25.67 | Schema validation | Validating plugin configuration and data schemas |
| Hono | ^4.11.7 | Web framework | Creating plugin routes and API endpoints |
| drizzle-kit | ^0.30.0 | Migration tools | Development workflow for schema management (not runtime) |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Raw SQL migrations | Drizzle schema files | Drizzle provides type safety but SonicJS convention is SQL files for clarity and compatibility |
| PluginBuilder | Manual Plugin object | Builder provides fluent API and validation, manual is more flexible but error-prone |
| Service class lifecycle | Inline lifecycle functions | Service class enables state management and testing, inline is simpler for trivial plugins |

**Installation:**
```bash
# Already installed in SonicJS projects
# Core dependencies managed at app level
```

## Architecture Patterns

### Recommended Project Structure
```
src/plugins/redirect-management/
├── index.ts                 # Plugin entry point with PluginBuilder
├── manifest.json            # Plugin metadata (id, name, version, settings schema)
├── types.ts                 # TypeScript interfaces for plugin data types
├── services/
│   └── redirect.ts          # Service class with lifecycle hooks and business logic
├── routes/
│   ├── admin.ts             # Admin API routes (settings, CRUD)
│   └── public.ts            # Public routes (redirect handling)
├── components/
│   └── settings-page.ts     # Admin UI component templates
├── migrations/
│   └── 001_redirect_plugin.sql  # Database schema migration
└── test/
    └── redirect.spec.ts     # Unit tests
```

### Pattern 1: PluginBuilder Fluent API
**What:** Use PluginBuilder.create() to construct plugin definition with chained method calls for routes, services, admin pages, and lifecycle hooks.

**When to use:** Always for SonicJS plugins - this is the standard approach.

**Example:**
```typescript
// Source: /Users/andrewhaas/Projects/SonicJS/sonicjs/my-sonicjs-app/src/plugins/contact-form/index.ts
import { PluginBuilder } from '@sonicjs-cms/core'
import type { Plugin, PluginContext } from '@sonicjs-cms/core'
import manifest from './manifest.json'
import { RedirectService } from './services/redirect'
import adminRoutes from './routes/admin'

export function createRedirectPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: manifest.id,
    version: manifest.version,
    description: manifest.description
  })

  builder.metadata({
    author: { name: manifest.author },
    license: manifest.license,
    compatibility: '^2.0.0'
  })

  // Routes
  builder.addRoute('/admin/plugins/redirect-management', adminRoutes, {
    description: 'Redirect admin routes',
    requiresAuth: true,
    priority: 100
  })

  // Admin page
  builder.addAdminPage(
    '/redirect-management/settings',
    'Redirect Management',
    'RedirectSettings',
    {
      description: 'Manage URL redirects',
      icon: 'arrow-right',
      permissions: ['admin', 'redirect.manage']
    }
  )

  // Menu item
  builder.addMenuItem('Redirects', '/admin/plugins/redirect-management/settings', {
    icon: 'arrow-right',
    order: 85
  })

  // Service registration
  let redirectService: RedirectService | null = null

  builder.addService('redirectService', {
    implementation: RedirectService,
    description: 'Redirect management service',
    singleton: true
  })

  // Lifecycle hooks
  builder.lifecycle({
    install: async (context: PluginContext) => {
      redirectService = new RedirectService(context.db)
      await redirectService.install()
      console.log('Redirect plugin installed')
    },
    activate: async (context: PluginContext) => {
      redirectService = new RedirectService(context.db)
      await redirectService.activate()
      console.log('Redirect plugin activated')
    },
    deactivate: async (context: PluginContext) => {
      if (redirectService) {
        await redirectService.deactivate()
        redirectService = null
      }
      console.log('Redirect plugin deactivated')
    },
    uninstall: async (context: PluginContext) => {
      if (redirectService) {
        await redirectService.uninstall()
        redirectService = null
      }
      console.log('Redirect plugin uninstalled')
    }
  })

  return builder.build()
}

export default createRedirectPlugin()
```

### Pattern 2: Service Class with Lifecycle Methods
**What:** Create a service class that encapsulates business logic and implements lifecycle methods (install, activate, deactivate, uninstall).

**When to use:** For plugins with database operations, settings management, or stateful operations.

**Example:**
```typescript
// Source: /Users/andrewhaas/Projects/SonicJS/sonicjs/my-sonicjs-app/src/plugins/contact-form/services/contact.ts
import type { D1Database } from '@cloudflare/workers-types'
import manifest from '../manifest.json'

export class RedirectService {
  constructor(private db: D1Database) {}

  async install(): Promise<void> {
    // Insert plugin entry into plugins table with default settings
    await this.db
      .prepare(`
        INSERT INTO plugins (
          id, name, display_name, description, version, author,
          category, status, settings, installed_at, last_updated
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'inactive', ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          display_name = excluded.display_name,
          version = excluded.version,
          updated_at = excluded.last_updated
      `)
      .bind(
        manifest.id,
        manifest.id,
        manifest.name,
        manifest.description,
        manifest.version,
        manifest.author,
        manifest.category,
        JSON.stringify(this.getDefaultSettings()),
        Date.now(),
        Date.now()
      )
      .run()
  }

  async activate(): Promise<void> {
    await this.db
      .prepare(`UPDATE plugins SET status = 'active', last_updated = ? WHERE id = ?`)
      .bind(Date.now(), manifest.id)
      .run()
  }

  async deactivate(): Promise<void> {
    await this.db
      .prepare(`UPDATE plugins SET status = 'inactive', last_updated = ? WHERE id = ?`)
      .bind(Date.now(), manifest.id)
      .run()
  }

  async uninstall(): Promise<void> {
    await this.db
      .prepare(`DELETE FROM plugins WHERE id = ?`)
      .bind(manifest.id)
      .run()
  }

  private getDefaultSettings() {
    return {
      // Plugin-specific settings
    }
  }
}
```

### Pattern 3: SQL Migration for Plugin Schema
**What:** Create a numbered SQL migration file that inserts plugin metadata, creates tables, and seeds initial data.

**When to use:** Every plugin needs a migration to register itself and create any custom tables.

**Example:**
```sql
-- Source: /Users/andrewhaas/Projects/SonicJS/sonicjs/my-sonicjs-app/migrations/031_contact_form_plugin.sql
-- Redirect Management Plugin Migration

-- Insert plugin entry into plugins table
INSERT INTO plugins (
  id,
  name,
  display_name,
  description,
  version,
  author,
  category,
  status,
  settings,
  installed_at,
  last_updated
) VALUES (
  'redirect-management',
  'redirect-management',
  'Redirect Management',
  'URL redirect management with exact, partial, and regex matching',
  '1.0.0',
  'SonicJS Community',
  'utilities',
  'inactive',
  json('{"enabled": true}'),
  strftime('%s', 'now') * 1000,
  strftime('%s', 'now') * 1000
)
ON CONFLICT(id) DO UPDATE SET
  display_name = excluded.display_name,
  description = excluded.description,
  version = excluded.version,
  updated_at = excluded.last_updated;

-- Create redirects table
CREATE TABLE IF NOT EXISTS redirects (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  destination TEXT NOT NULL,
  match_type INTEGER NOT NULL DEFAULT 0, -- 0=exact, 1=partial, 2=regex
  status_code INTEGER NOT NULL DEFAULT 301,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_redirects_source ON redirects(source);
CREATE INDEX IF NOT EXISTS idx_redirects_active ON redirects(is_active);
CREATE INDEX IF NOT EXISTS idx_redirects_match_type ON redirects(match_type);

-- Create analytics table (separate from main table)
CREATE TABLE IF NOT EXISTS redirect_analytics (
  id TEXT PRIMARY KEY,
  redirect_id TEXT NOT NULL REFERENCES redirects(id) ON DELETE CASCADE,
  hit_count INTEGER NOT NULL DEFAULT 0,
  last_hit_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_redirect_analytics_redirect_id ON redirect_analytics(redirect_id);

-- Insert collection schema for redirects
INSERT INTO collections (
  id,
  name,
  display_name,
  description,
  schema,
  is_active,
  created_at,
  updated_at
) VALUES (
  'redirects',
  'redirects',
  'Redirects',
  'URL redirect management',
  json('{
    "fields": [
      {"name": "source", "type": "text", "required": true, "label": "Source URL"},
      {"name": "destination", "type": "text", "required": true, "label": "Destination URL"},
      {"name": "match_type", "type": "select", "required": true, "label": "Match Type", "options": [
        {"value": 0, "label": "Exact"},
        {"value": 1, "label": "Partial"},
        {"value": 2, "label": "Regex"}
      ]},
      {"name": "status_code", "type": "number", "required": true, "label": "Status Code", "default": 301},
      {"name": "is_active", "type": "boolean", "required": true, "label": "Active", "default": true}
    ]
  }'),
  1,
  strftime('%s', 'now') * 1000,
  strftime('%s', 'now') * 1000
)
ON CONFLICT(id) DO UPDATE SET
  display_name = excluded.display_name,
  schema = excluded.schema,
  updated_at = excluded.updated_at;

-- Insert sample redirect data
INSERT OR IGNORE INTO redirects (id, source, destination, match_type, status_code, is_active, created_by, created_at, updated_at) VALUES
  ('sample-redirect-1', '/old-page', '/new-page', 0, 301, 1, 'admin-user-id', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
  ('sample-redirect-2', '/blog/old-post', '/blog/new-post', 0, 302, 1, 'admin-user-id', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
  ('sample-redirect-3', '/temp-page', '/permanent-page', 0, 307, 0, 'admin-user-id', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
  ('sample-redirect-4', '/gone-page', '/gone-page', 0, 410, 1, 'admin-user-id', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000);
```

### Pattern 4: Manifest.json Structure
**What:** Define plugin metadata in a manifest.json file that describes the plugin's identity, settings schema, permissions, and routes.

**When to use:** Every plugin needs a manifest for registration and configuration.

**Example:**
```json
{
  "id": "redirect-management",
  "name": "Redirect Management",
  "version": "1.0.0",
  "description": "URL redirect management with exact, partial, and regex matching",
  "author": "SonicJS Community",
  "homepage": "https://sonicjs.com/plugins/redirect-management",
  "license": "MIT",
  "category": "utilities",
  "tags": ["redirects", "seo", "urls", "utilities"],
  "dependencies": [],
  "settings": {
    "enabled": {
      "type": "boolean",
      "label": "Enable Redirects",
      "description": "Enable or disable redirect processing",
      "default": true
    }
  },
  "permissions": {
    "redirect.manage": "Manage redirects and settings",
    "redirect.view": "View redirects"
  }
}
```

### Anti-Patterns to Avoid
- **Inline migrations in code:** Always use SQL migration files, not programmatic table creation in service methods. Migration files are version-controlled, auditable, and follow SonicJS conventions.
- **Direct database manipulation without service layer:** Don't put SQL queries in routes or components. Use a service class to encapsulate database operations and business logic.
- **Missing ON CONFLICT clauses:** Always include `ON CONFLICT DO UPDATE` for plugin registration to handle reinstalls gracefully.
- **Forgetting indexes:** Collections that will be queried frequently need indexes on lookup fields (source URL, active status, etc.).
- **Not using timestamps:** SonicJS uses millisecond timestamps (Date.now()), not seconds or SQL date functions for consistency across the system.

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Plugin lifecycle management | Custom event emitters | PluginBuilder.lifecycle() | PluginBuilder integrates with SonicJS plugin manager, handles context injection, and provides standardized hooks |
| Database migrations | Custom version tracking | MigrationService | SonicJS has a migration tracking system with auto-detection, rollback capability, and proper transaction handling |
| Settings storage | Custom tables | plugins.settings JSON column | SonicJS stores all plugin settings in the plugins table as JSON, accessible via service methods |
| Collection schema definition | TypeScript-only types | collections table JSON schema + TypeScript types | Collections must be registered in the database for the admin UI to generate forms and validate data |
| Admin page registration | Manual route creation | builder.addAdminPage() | Admin pages integrate with SonicJS navigation, permission system, and page rendering automatically |

**Key insight:** SonicJS provides a comprehensive plugin system with lifecycle management, migration tracking, settings storage, and admin integration. Use these built-in systems rather than building custom solutions that won't integrate properly with the core platform.

## Common Pitfalls

### Pitfall 1: Migration Numbering Conflicts
**What goes wrong:** Multiple developers create migrations with the same number on different branches, causing conflicts when merging.

**Why it happens:** D1 migrations use sequential numbers (001, 002, 003) and the system tracks which have been applied by ID.

**How to avoid:**
- Coordinate migration numbers with the team or use a shared migration log
- Check the migrations/ directory before creating a new migration file
- Use feature branch naming to identify migration ownership (e.g., 040_feature_redirects.sql)
- The migration system can handle out-of-order numbers, but duplicate numbers cause confusion

**Warning signs:** Git merge conflicts in migrations/ directory, migrations appearing as "already applied" on one environment but "pending" on another.

### Pitfall 2: Forgetting Collection Registration
**What goes wrong:** Creating a custom table but not registering it in the `collections` table, breaking admin UI generation and content API.

**Why it happens:** Developers familiar with traditional SQL databases create tables without understanding SonicJS's collection-based content model.

**How to avoid:**
- If your data should appear in the admin UI as content, register it in the `collections` table with a JSON schema
- If it's internal plugin data (analytics, logs, settings), it can be a standalone table without collection registration
- For redirect management, the redirects table IS the primary content and should be registered as a collection

**Warning signs:** Table exists but doesn't appear in admin content list, content API endpoints return empty results, admin forms can't be generated.

### Pitfall 3: Lifecycle Hook Execution Order
**What goes wrong:** Plugin accesses database or services before they're initialized, causing runtime errors.

**Why it happens:** Misunderstanding the lifecycle hook execution sequence: install → activate, and deactivate → uninstall.

**How to avoid:**
- `install`: Called once when plugin is first installed - create database schema, insert default data
- `activate`: Called every time the app starts if plugin is enabled - initialize services, register hooks
- `deactivate`: Called when plugin is disabled - clean up services, unregister hooks
- `uninstall`: Called when plugin is removed - drop tables, delete data (use with caution)

**Warning signs:** "Database not available" errors, null reference errors in lifecycle hooks, services not initialized when routes are called.

### Pitfall 4: JSON Column Type Mismatch
**What goes wrong:** Settings retrieved from the database are strings, not objects, causing JSON.parse errors or type confusion.

**Why it happens:** D1/SQLite stores JSON as TEXT, requiring manual serialization/deserialization.

**How to avoid:**
- Always use `JSON.parse()` when reading from settings/data columns
- Always use `JSON.stringify()` when writing to settings/data columns
- Use the `json()` SQL function in migrations for default values: `json('{"key": "value"}')`
- Type your service methods to return parsed objects, not strings

**Warning signs:** "Cannot read property of string" errors, settings appear as "[object Object]" in the database, boolean settings become string "true"/"false".

### Pitfall 5: Missing Foreign Key Constraints
**What goes wrong:** Orphaned records remain after deleting parent records (e.g., redirect analytics after deleting redirect).

**Why it happens:** Not using REFERENCES with ON DELETE CASCADE in table definitions.

**How to avoid:**
- Use `REFERENCES table(column) ON DELETE CASCADE` for parent-child relationships
- For analytics/logs where orphans are acceptable, use `REFERENCES table(column)` without CASCADE
- Document the cascading behavior in migration comments
- Consider soft deletes (is_deleted flag) instead of hard deletes for audit trails

**Warning signs:** Orphaned analytics records, broken foreign key references, data integrity issues.

## Code Examples

Verified patterns from official sources:

### Plugin Registration in Migration
```sql
-- Source: SonicJS contact-form plugin migration pattern
-- Insert plugin entry with settings and metadata
INSERT INTO plugins (
  id,
  name,
  display_name,
  description,
  version,
  author,
  category,
  status,
  settings,
  installed_at,
  last_updated
) VALUES (
  'redirect-management',
  'redirect-management',
  'Redirect Management',
  'URL redirect management plugin',
  '1.0.0',
  'SonicJS Community',
  'utilities',
  'inactive',
  json('{"enabled": true}'),
  strftime('%s', 'now') * 1000,
  strftime('%s', 'now') * 1000
)
ON CONFLICT(id) DO UPDATE SET
  display_name = excluded.display_name,
  description = excluded.description,
  version = excluded.version,
  updated_at = excluded.last_updated;
```

### Table Creation with Proper Indexing
```sql
-- Source: SonicJS core migrations pattern
-- Create main redirects table
CREATE TABLE IF NOT EXISTS redirects (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  destination TEXT NOT NULL,
  match_type INTEGER NOT NULL DEFAULT 0,
  status_code INTEGER NOT NULL DEFAULT 301,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Create indexes for query performance
CREATE INDEX IF NOT EXISTS idx_redirects_source ON redirects(source);
CREATE INDEX IF NOT EXISTS idx_redirects_active ON redirects(is_active);
CREATE INDEX IF NOT EXISTS idx_redirects_match_type ON redirects(match_type);
```

### Service Class Database Operations
```typescript
// Source: Contact-form service pattern
async saveSettings(settings: RedirectSettings): Promise<void> {
  try {
    const existing = await this.db
      .prepare(`SELECT id, status FROM plugins WHERE id = ?`)
      .bind(manifest.id)
      .first()

    if (existing) {
      await this.db
        .prepare(`UPDATE plugins SET settings = ?, last_updated = ? WHERE id = ?`)
        .bind(JSON.stringify(settings), Date.now(), manifest.id)
        .run()
    } else {
      await this.db
        .prepare(`
          INSERT INTO plugins (id, name, display_name, description, version, author, category, status, settings, installed_at, last_updated)
          VALUES (?, ?, ?, ?, ?, ?, ?, 'inactive', ?, ?, ?)
        `)
        .bind(
          manifest.id,
          manifest.name,
          manifest.name,
          manifest.description,
          manifest.version,
          manifest.author,
          manifest.category,
          JSON.stringify(settings),
          Date.now(),
          Date.now()
        )
        .run()
    }
  } catch (error) {
    console.error('Error saving settings:', error)
    throw new Error('Failed to save settings')
  }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Manual plugin registration | PluginBuilder fluent API | v2.0 (2025) | Type-safe plugin construction with builder validation |
| Individual migration execution | MigrationService with auto-detection | v2.0 | Handles migration tracking, rollback, and idempotency |
| Separate table per content type | Unified collections + content tables | v1.0 design | Enables dynamic schema, admin UI generation, and API consistency |
| String-based settings | JSON column with schema validation | v2.0 | Type-safe settings with validation and defaults |
| Global service instances | Plugin context with scoped services | v2.0 | Better isolation, testing, and lifecycle management |

**Deprecated/outdated:**
- **Direct PluginRegistry usage:** Use PluginBuilder.create() instead of manually creating Plugin objects and calling registry.register()
- **Hardcoded admin routes:** Use builder.addAdminPage() and builder.addMenuItem() for automatic integration with admin navigation
- **Manual migration tracking:** Don't create custom migration version tables; use the built-in MigrationService

## Open Questions

Things that couldn't be fully resolved:

1. **Collection vs. Custom Table Strategy**
   - What we know: SonicJS has both a flexible `collections`/`content` system for dynamic content and support for custom tables with fixed schemas
   - What's unclear: Whether the redirects should be stored in the `content` table (as a collection) or a dedicated `redirects` table
   - Recommendation: Use a dedicated `redirects` table for performance (direct queries without JSON parsing) and register it as a collection for admin UI support. The analytics table should be separate and NOT a collection.

2. **Migration Rollback Strategy**
   - What we know: MigrationService tracks applied migrations and can detect out-of-order migrations
   - What's unclear: Whether D1 supports transaction rollback for failed migrations, and if there's a built-in rollback mechanism
   - Recommendation: Write idempotent migrations with `IF NOT EXISTS`, `ON CONFLICT`, and error handling. Test migrations thoroughly in local environment before applying to production.

3. **Plugin Settings Schema Validation**
   - What we know: Settings are stored as JSON in the plugins table, and manifest.json can declare settings structure
   - What's unclear: Whether SonicJS validates settings against the manifest schema automatically, or if plugins must implement validation
   - Recommendation: Implement Zod validation in the service class for settings to ensure type safety and catch configuration errors early.

## Sources

### Primary (HIGH confidence)
- SonicJS contact-form plugin source code - Verified plugin architecture patterns
- SonicJS core type definitions (plugin.ts, plugin-builder.ts) - Official API contracts
- SonicJS migration files (001_initial_schema.sql, 031_contact_form_plugin.sql) - Database schema patterns
- MigrationService implementation - Migration execution and tracking logic
- Package.json dependencies - Confirmed versions (Drizzle 0.44.2, TypeScript 5.8.3, Hono 4.11.7)

### Secondary (MEDIUM confidence)
- [Drizzle ORM - Migrations](https://orm.drizzle.team/docs/migrations) - Migration best practices
- [Cloudflare D1 Migrations Documentation](https://developers.cloudflare.com/d1/reference/migrations/) - D1-specific migration features
- [D1 SQLite: Schema, migrations and seeds - This Dot Labs](https://www.thisdot.co/blog/d1-sqlite-schema-migrations-and-seeds) - D1 patterns and practices
- [Node.js Advanced Patterns: Plugin Manager | Medium](https://v-checha.medium.com/node-js-advanced-patterns-plugin-manager-44adb72aa6bb) - Plugin architecture patterns
- [Designing a Plugin System in TypeScript - DEV Community](https://dev.to/hexshift/designing-a-plugin-system-in-typescript-for-modular-web-applications-4db5) - TypeScript plugin design

### Tertiary (LOW confidence)
- [Migration best practices - StudyRaid](https://app.studyraid.com/en/read/11288/352164/migration-best-practices) - General migration guidance (not D1-specific)
- [D1 Community Discussion on Migration Naming](https://community.cloudflare.com/t/d1-migrations-store-migration-name-instead-of-sequence-number/832687) - Community feedback on D1 limitations

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Verified from package.json and core dependencies
- Architecture: HIGH - Patterns directly extracted from contact-form plugin and core types
- Pitfalls: MEDIUM-HIGH - Based on observed patterns in codebase and database schema design, some inferred from common SQLite/plugin issues

**Research date:** 2026-01-30
**Valid until:** 2026-02-28 (30 days - stable architecture, unlikely to change rapidly)
