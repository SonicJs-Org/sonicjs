/**
 * migrations.ts — the Views plugin's storage schema, provisioned idempotently from
 * `onBoot` (the menu-plugin timing + the global-variables SQL-string pattern; core has
 * no plugin migration runner). Every statement is `IF NOT EXISTS`-idempotent, so a boot
 * re-run is a no-op.
 *
 * Consolidated from the plugin's origin history (the origin schema migrations + the two
 * 2026-06-30 view_displays alters), with vendor-neutral table names (`views`,
 * `view_displays`).
 *
 * No FKs into core tables by design (plugin tables must not couple to host schema);
 * `view_id` keeps its intra-plugin FK. `collection_id` references a `document_types` id
 * by VALUE (resolved through the view-collection-resolver, not a constraint).
 *
 * Tenant scoping: both tables carry `tenant_id` (default `'default'`, matching the
 * document-model convention — see `getRequestTenant()`). `name`/`path` uniqueness is
 * per-tenant (`UNIQUE(tenant_id, name)` / `UNIQUE(tenant_id, path)`), not global — two
 * tenants must each be free to use "homepage" without colliding. `share_token` stays
 * globally unique on purpose: it's a random, unguessable secret used as the SOLE lookup
 * key for an anonymous request that has no other way to know which tenant it belongs to,
 * so scoping it by tenant would add nothing (the token already fully identifies the row).
 */
import type { D1Database } from '@cloudflare/workers-types'

export const VIEWS_MIGRATION_STATEMENTS: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS views (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    display_name TEXT,
    description TEXT,
    collection_id TEXT,
    filter_config TEXT,
    sort_config TEXT,
    columns_config TEXT,
    page_size INTEGER DEFAULT 25,
    is_default INTEGER DEFAULT 0,
    -- Public-API opt-in: a view is PRIVATE by default (0). The anonymous JSON/CSV
    -- endpoint GET /api/views/:name only serves a view with is_public = 1 AND whose
    -- backing collection grants public read. Private views stay fully usable in the
    -- authed admin builder.
    is_public INTEGER NOT NULL DEFAULT 0,
    status TEXT DEFAULT 'active',
    created_by TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS view_displays (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    view_id TEXT NOT NULL REFERENCES views(id) ON DELETE CASCADE,
    display_type TEXT NOT NULL,
    path TEXT,
    config TEXT NOT NULL,
    is_public INTEGER NOT NULL DEFAULT 0,
    share_token TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_views_collection ON views(collection_id)`,
  `CREATE INDEX IF NOT EXISTS idx_views_status ON views(status)`,
  `CREATE INDEX IF NOT EXISTS idx_views_tenant ON views(tenant_id)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_views_tenant_name ON views(tenant_id, name)`,
  `CREATE INDEX IF NOT EXISTS idx_view_displays_view ON view_displays(view_id)`,
  `CREATE INDEX IF NOT EXISTS idx_view_displays_tenant ON view_displays(tenant_id)`,
  // One published display per public slug PER TENANT (NULL paths — unpublished — unconstrained).
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_view_displays_tenant_path
     ON view_displays(tenant_id, path) WHERE path IS NOT NULL`,
  // One display per share token; tokens are '_'-prefixed so the token and path
  // value-spaces are provably disjoint. Deliberately NOT tenant-scoped — see file header.
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_view_displays_share_token
     ON view_displays(share_token) WHERE share_token IS NOT NULL`,
]

/**
 * Additive column migrations for tables that predate a column. SQLite has no
 * `ADD COLUMN IF NOT EXISTS`, so each is run in its own try/catch at boot and a
 * "duplicate column name" is swallowed (fresh installs already have it from the
 * CREATE above; only a pre-existing table needs the ALTER).
 */
export const VIEWS_COLUMN_MIGRATIONS: readonly string[] = [
  `ALTER TABLE views ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE views ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'`,
  `ALTER TABLE view_displays ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'`,
]

/**
 * Self-heal for an install that provisioned `views`/`view_displays` before tenant scoping
 * existed. `ADD COLUMN` (above) gets `tenant_id` onto pre-existing rows, but SQLite has no
 * `ALTER TABLE ... DROP CONSTRAINT` — the OLD single-column `UNIQUE` on `views.name` (an
 * automatic index SQLite creates for an inline column constraint) and the old
 * `idx_view_displays_path` (global, not tenant-scoped) both survive the ADD COLUMN
 * untouched, and would keep blocking a second tenant from reusing a name/path the first
 * tenant already has. Detected via `PRAGMA index_list` (`origin = 'u'` = created by a
 * UNIQUE column constraint, not a `CREATE INDEX` statement) so this only runs the rebuild
 * once — a fresh install never has the old constraint and skips straight through.
 *
 * `view_displays` is rebuilt first: it only references `views` via FK (nothing references
 * IT), so dropping and recreating it is safe regardless of FK enforcement state. `views` is
 * rebuilt after, with `PRAGMA foreign_keys = OFF` bracketing both (D1's FK enforcement is
 * not guaranteed either way — this makes the intent explicit rather than relying on it).
 */
export async function ensureViewsTenantUniqueness(db: D1Database): Promise<void> {
  try {
    const viewsIndexes = await db.prepare(`PRAGMA index_list('views')`).all<{ name: string; origin: string }>()
    const hasOldViewsUnique = (viewsIndexes.results ?? []).some((i) => i.origin === 'u')

    const displaysIndexes = await db.prepare(`PRAGMA index_list('view_displays')`).all<{ name: string; origin: string }>()
    const hasOldPathIndex = (displaysIndexes.results ?? []).some((i) => i.name === 'idx_view_displays_path')

    if (!hasOldViewsUnique && !hasOldPathIndex) return // already migrated (or a fresh install)

    await db.prepare(`PRAGMA foreign_keys = OFF`).run()
    try {
      if (hasOldPathIndex) {
        await db.batch([
          db.prepare(`CREATE TABLE view_displays_new (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            view_id TEXT NOT NULL REFERENCES views(id) ON DELETE CASCADE,
            display_type TEXT NOT NULL,
            path TEXT,
            config TEXT NOT NULL,
            is_public INTEGER NOT NULL DEFAULT 0,
            share_token TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
          )`),
          db.prepare(`INSERT INTO view_displays_new SELECT id, COALESCE(tenant_id, 'default'), view_id, display_type, path, config, is_public, share_token, created_at, updated_at FROM view_displays`),
          db.prepare(`DROP TABLE view_displays`),
          db.prepare(`ALTER TABLE view_displays_new RENAME TO view_displays`),
          db.prepare(`CREATE INDEX IF NOT EXISTS idx_view_displays_view ON view_displays(view_id)`),
          db.prepare(`CREATE INDEX IF NOT EXISTS idx_view_displays_tenant ON view_displays(tenant_id)`),
          db.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS idx_view_displays_tenant_path ON view_displays(tenant_id, path) WHERE path IS NOT NULL`),
          db.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS idx_view_displays_share_token ON view_displays(share_token) WHERE share_token IS NOT NULL`),
        ])
      }

      if (hasOldViewsUnique) {
        await db.batch([
          db.prepare(`CREATE TABLE views_new (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            name TEXT NOT NULL,
            display_name TEXT,
            description TEXT,
            collection_id TEXT,
            filter_config TEXT,
            sort_config TEXT,
            columns_config TEXT,
            page_size INTEGER DEFAULT 25,
            is_default INTEGER DEFAULT 0,
            is_public INTEGER NOT NULL DEFAULT 0,
            status TEXT DEFAULT 'active',
            created_by TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
          )`),
          db.prepare(`INSERT INTO views_new SELECT id, COALESCE(tenant_id, 'default'), name, display_name, description, collection_id, filter_config, sort_config, columns_config, page_size, is_default, is_public, status, created_by, created_at, updated_at FROM views`),
          db.prepare(`DROP TABLE views`),
          db.prepare(`ALTER TABLE views_new RENAME TO views`),
          db.prepare(`CREATE INDEX IF NOT EXISTS idx_views_collection ON views(collection_id)`),
          db.prepare(`CREATE INDEX IF NOT EXISTS idx_views_status ON views(status)`),
          db.prepare(`CREATE INDEX IF NOT EXISTS idx_views_tenant ON views(tenant_id)`),
          db.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS idx_views_tenant_name ON views(tenant_id, name)`),
        ])
      }
    } finally {
      // Restore FK enforcement even if a batch above failed partway through — each batch is
      // transactional (rolls back cleanly on failure, so no data corruption either way), but
      // without this a failed rebuild would leave FK enforcement OFF for the rest of the
      // connection's life, silently, until the next successful self-heal run.
      await db.prepare(`PRAGMA foreign_keys = ON`).run()
    }
    console.log('[views-plugin] Self-healed per-tenant uniqueness on views/view_displays')
  } catch (err) {
    console.error('[views-plugin] per-tenant uniqueness self-heal failed:', err instanceof Error ? err.message : String(err))
  }
}
