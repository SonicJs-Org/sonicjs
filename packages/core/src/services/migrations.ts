import { D1Database } from '@cloudflare/workers-types'
import { bundledMigrations } from '../db/migrations-bundle'
import { ensureScalarSchema } from './document-scalar-schema'
import type { QueryableField } from '../schemas/document'

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
   * Ensure the `documents` table exposes every queryable VIRTUAL generated column + index (D45).
   * Data-driven repair: reconciles from each active type's `queryable_fields` rather than a hardcoded
   * list, so it stays in sync with whatever types are registered. Generation of these columns is owned
   * by DocumentTypeRegistry.register() (via ensureScalarSchema); this pass is a bootstrap safety net for
   * a DB that has document_types rows but lost columns (e.g. table rebuilt). Idempotent.
   */
  private async ensureDocumentGeneratedColumns(): Promise<void> {
    if (!(await this.checkTablesExist(['document_types']))) return
    const rows = await this.db
      .prepare('SELECT id, queryable_fields FROM document_types WHERE is_active = 1')
      .all<{ id: string; queryable_fields: string }>()
    for (const row of rows.results ?? []) {
      let fields: QueryableField[]
      try {
        fields = JSON.parse(row.queryable_fields)
      } catch {
        continue
      }
      await ensureScalarSchema(this.db, row.id, fields)
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

    return {
      valid: issues.length === 0,
      issues
    }
  }
}
