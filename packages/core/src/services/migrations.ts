import { D1Database } from '@cloudflare/workers-types'
import { bundledMigrations } from '../db/migrations-bundle'

export interface Migration {
  id: string
  name: string
  filename: string
  description?: string
  applied: boolean
  appliedAt?: string
  size?: number
}

export interface MigrationStatus {
  totalMigrations: number
  appliedMigrations: number
  pendingMigrations: number
  lastApplied?: string
  migrations: Migration[]
}

export class MigrationService {
  constructor(private db: D1Database) {}

  /**
   * Cloudflare D1 owns migration bookkeeping through `d1_migrations`.
   * SonicJS intentionally does not create its own tracking table.
   */
  async initializeMigrationsTable(): Promise<void> {
    // Kept as a no-op for compatibility with older callers.
  }

  /**
   * Get all available migrations from the bundled migrations
   */
  async getAvailableMigrations(): Promise<Migration[]> {
    const migrations: Migration[] = []
    const appliedMigrations = await this.getD1AppliedMigrations()
    await this.ensureSchemaCompatibility()

    // Use bundled migrations as the source of truth
    for (const bundled of bundledMigrations) {
      const applied = appliedMigrations.has(bundled.id)
      const appliedData = appliedMigrations.get(bundled.id)

      migrations.push({
        id: bundled.id,
        name: bundled.name,
        filename: bundled.filename,
        description: bundled.description,
        applied,
        appliedAt: applied ? appliedData?.applied_at : undefined,
        size: bundled.sql.length
      })
    }

    return migrations
  }

  /**
   * Read Wrangler/D1's canonical migration table. If the table is absent, no
   * migrations have been applied by the supported migration runner yet.
   */
  private async getD1AppliedMigrations(): Promise<Map<string, any>> {
    try {
      const appliedResult = await this.db.prepare(
        'SELECT name, applied_at FROM d1_migrations ORDER BY applied_at ASC'
      ).all()

      return new Map(
        (appliedResult.results ?? [])
          .map((row: any) => {
            const filename = String(row.name ?? '')
            const id = filename.match(/^(\d+)/)?.[1]
            if (!id) return null
            return [id, {
              id,
              name: filename,
              filename,
              applied_at: row.applied_at
            }]
          })
          .filter((entry): entry is [string, any] => entry !== null)
      )
    } catch (error) {
      return new Map()
    }
  }

  /**
   * Run idempotent compatibility repairs that are safe outside migration state.
   */
  async ensureSchemaCompatibility(): Promise<void> {
    if (await this.checkTablesExist(['documents'])) {
      await this.ensureDocumentGeneratedColumns()
    }
  }

  /**
   * Ensure the `documents` table exposes every queryable VIRTUAL generated column (D45). Safe to run on
   * every bootstrap: existing columns are skipped, missing ones are added, and the unavoidable race of a
   * concurrent add surfaces as a swallowed "duplicate column name" error.
   */
  private async ensureDocumentGeneratedColumns(): Promise<void> {
    // (column name, full ADD COLUMN body) — kept in sync with migrations 043 + 044.
    const columns: Array<[string, string]> = [
      ['q_faq_category',    "q_faq_category TEXT AS (json_extract(data, '$.category')) VIRTUAL"],
      ['q_faq_sort_order',  "q_faq_sort_order INTEGER AS (json_extract(data, '$.sortOrder')) VIRTUAL"],
      ['q_tst_rating',      "q_tst_rating INTEGER AS (json_extract(data, '$.rating')) VIRTUAL"],
      ['q_tst_company',     "q_tst_company TEXT AS (json_extract(data, '$.authorCompany')) VIRTUAL"],
      ['q_tst_sort_order',  "q_tst_sort_order INTEGER AS (json_extract(data, '$.sortOrder')) VIRTUAL"],
      ['q_msg_review',      "q_msg_review TEXT AS (json_extract(data, '$.reviewStatus')) VIRTUAL"],
      ['q_msg_email',       "q_msg_email TEXT AS (json_extract(data, '$.email')) VIRTUAL"],
      ['q_media_mime',      "q_media_mime TEXT AS (json_extract(data, '$.mimeType')) VIRTUAL"],
      ['q_media_folder',    "q_media_folder TEXT AS (json_extract(data, '$.folder')) VIRTUAL"],
      ['q_media_size',      "q_media_size INTEGER AS (json_extract(data, '$.size')) VIRTUAL"],
      ['q_blog_difficulty', "q_blog_difficulty TEXT AS (json_extract(data, '$.difficulty')) VIRTUAL"],
      ['q_blog_author',     "q_blog_author TEXT AS (json_extract(data, '$.author')) VIRTUAL"],
      // email_log document type (plugin-system/email-reconciliation)
      ['q_email_status',   "q_email_status TEXT AS (json_extract(data, '$.status')) VIRTUAL"],
      ['q_email_provider', "q_email_provider TEXT AS (json_extract(data, '$.provider')) VIRTUAL"],
      ['q_email_flow',     "q_email_flow TEXT AS (json_extract(data, '$.flow')) VIRTUAL"],
      ['q_email_to',       "q_email_to TEXT AS (json_extract(data, '$.toEmail')) VIRTUAL"],
    ]
    // Note: pragma_table_info does NOT list VIRTUAL generated columns — use table_xinfo, which does.
    let existing = new Set<string>()
    try {
      const info = await this.db.prepare("SELECT name FROM pragma_table_xinfo('documents')").all()
      existing = new Set((info?.results ?? []).map((r: any) => r.name))
    } catch {
      // table_xinfo unavailable — fall back to attempting every ALTER (duplicate errors are swallowed).
    }
    for (const [name, body] of columns) {
      if (existing.has(name)) continue
      try {
        await this.db.prepare(`ALTER TABLE documents ADD COLUMN ${body}`).run()
        console.log(`[Migration] D45: added missing documents.${name}`)
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error)
        if (!msg.includes('duplicate column name')) {
          console.error(`[Migration] D45: failed to add documents.${name}:`, msg)
        }
      }
    }
  }

  /**
   * Check if specific tables exist in the database
   */
  private async checkTablesExist(tableNames: string[]): Promise<boolean> {
    try {
      for (const tableName of tableNames) {
        const result = await this.db.prepare(
          `SELECT name FROM sqlite_master WHERE type='table' AND name=?`
        ).bind(tableName).first()

        if (!result) {
          return false
        }
      }
      return true
    } catch (error) {
      return false
    }
  }

  /**
   * Check if a specific column exists in a table
   */
  private async checkColumnExists(tableName: string, columnName: string): Promise<boolean> {
    try {
      const result = await this.db.prepare(
        `SELECT * FROM pragma_table_info(?) WHERE name = ?`
      ).bind(tableName, columnName).first()

      return !!result
    } catch (error) {
      return false
    }
  }

  /**
   * Get migration status summary
   */
  async getMigrationStatus(): Promise<MigrationStatus> {
    const migrations = await this.getAvailableMigrations()
    const appliedMigrations = migrations.filter(m => m.applied)
    const pendingMigrations = migrations.filter(m => !m.applied)

    const lastApplied = appliedMigrations.length > 0
      ? appliedMigrations[appliedMigrations.length - 1]?.appliedAt
      : undefined

    return {
      totalMigrations: migrations.length,
      appliedMigrations: appliedMigrations.length,
      pendingMigrations: pendingMigrations.length,
      lastApplied,
      migrations
    }
  }

  /**
   * D1 migration state is managed by Wrangler.
   */
  async markMigrationApplied(migrationId: string, name: string, filename: string): Promise<void> {
    void migrationId
    void name
    void filename
  }

  /**
   * D1 migration state is managed by Wrangler.
   */
  async removeMigrationApplied(migrationId: string): Promise<void> {
    void migrationId
  }

  /**
   * Check if a specific migration has been applied
   */
  async isMigrationApplied(migrationId: string): Promise<boolean> {
    const appliedMigrations = await this.getD1AppliedMigrations()
    return appliedMigrations.has(migrationId)
  }

  /**
   * Get the last applied migration
   */
  async getLastAppliedMigration(): Promise<Migration | null> {
    const migrations = await this.getAvailableMigrations()
    return migrations.filter(m => m.applied).at(-1) ?? null
  }

  /**
   * Run pending migrations
   */
  async runPendingMigrations(): Promise<{ success: boolean; message: string; applied: string[]; errors: string[] }> {
    return {
      success: false,
      message: 'Migrations are managed by Cloudflare D1. Run `wrangler d1 migrations apply DB --local` or `wrangler d1 migrations apply DB --remote`.',
      applied: [],
      errors: []
    }
  }

  /**
   * Validate database schema
   */
  async validateSchema(): Promise<{ valid: boolean; issues: string[] }> {
    const issues: string[] = []

    // Basic table existence checks
    const requiredTables = [
      'users', 'documents', 'document_types'
    ]

    for (const table of requiredTables) {
      try {
        await this.db.prepare(`SELECT COUNT(*) FROM ${table} LIMIT 1`).first()
      } catch (error) {
        issues.push(`Missing table: ${table}`)
      }
    }

    // Check for managed column in collections
    const hasManagedColumn = await this.checkColumnExists('collections', 'managed')
    if (!hasManagedColumn) {
      issues.push('Missing column: collections.managed')
    }

    return {
      valid: issues.length === 0,
      issues
    }
  }
}
