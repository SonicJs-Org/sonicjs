import { D1Database } from '@cloudflare/workers-types'
import { bundledMigrations, getMigrationSQLById, type BundledMigration } from '../db/migrations-bundle'

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
   * Initialize the migrations tracking table
   */
  async initializeMigrationsTable(): Promise<void> {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS migrations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        filename TEXT NOT NULL,
        applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        checksum TEXT
      )
    `

    await this.db.prepare(createTableQuery).run()
  }

  /**
   * Get all available migrations from the bundled migrations
   */
  async getAvailableMigrations(): Promise<Migration[]> {
    const migrations: Migration[] = []

    // Get applied migrations from database
    const appliedResult = await this.db.prepare(
      'SELECT id, name, filename, applied_at FROM migrations ORDER BY applied_at ASC'
    ).all()

    const appliedMigrations = new Map(
      appliedResult.results?.map((row: any) => [row.id, row]) || []
    )

    // Auto-detect applied migrations by checking if their tables exist
    await this.autoDetectAppliedMigrations(appliedMigrations)

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
   * Auto-detect applied migrations by checking if their tables exist
   */
  private async autoDetectAppliedMigrations(appliedMigrations: Map<string, any>): Promise<void> {
    // Check if basic schema tables exist (migration 001)
    if (!appliedMigrations.has('001')) {
      const hasBasicTables = await this.checkTablesExist(['users', 'content', 'collections', 'media'])
      if (hasBasicTables) {
        appliedMigrations.set('001', {
          id: '001',
          applied_at: new Date().toISOString(),
          name: 'Initial Schema',
          filename: '001_initial_schema.sql'
        })
        await this.markMigrationApplied('001', 'Initial Schema', '001_initial_schema.sql')
      }
    }

    // Check if FAQ tables exist (migration 002)
    // Migration 002 creates only the 'faqs' table
    if (!appliedMigrations.has('002')) {
      const hasFaqTables = await this.checkTablesExist(['faqs'])
      if (hasFaqTables) {
        appliedMigrations.set('002', {
          id: '002',
          applied_at: new Date().toISOString(),
          name: 'Faq Plugin',
          filename: '002_faq_plugin.sql'
        })
        await this.markMigrationApplied('002', 'Faq Plugin', '002_faq_plugin.sql')
      }
    }

    // Check if stage 5 enhancement tables exist (migration 003)
    // Migration 003 creates content_fields, content_relationships, workflow_templates tables
    if (!appliedMigrations.has('003')) {
      const hasStage5Tables = await this.checkTablesExist(['content_fields', 'content_relationships', 'workflow_templates'])
      if (hasStage5Tables) {
        appliedMigrations.set('003', {
          id: '003',
          applied_at: new Date().toISOString(),
          name: 'Stage 5 Enhancements',
          filename: '003_stage5_enhancements.sql'
        })
        await this.markMigrationApplied('003', 'Stage 5 Enhancements', '003_stage5_enhancements.sql')
      }
    }

    // Check if testimonials table exists (migration 012)
    if (!appliedMigrations.has('012')) {
      const hasTestimonialsTables = await this.checkTablesExist(['testimonials'])
      if (hasTestimonialsTables) {
        appliedMigrations.set('012', {
          id: '012',
          applied_at: new Date().toISOString(),
          name: 'Testimonials Plugin',
          filename: '012_testimonials_plugin.sql'
        })
        await this.markMigrationApplied('012', 'Testimonials Plugin', '012_testimonials_plugin.sql')
      }
    }

    // Check if code_examples table exists (migration 013)
    if (!appliedMigrations.has('013')) {
      const hasCodeExamplesTables = await this.checkTablesExist(['code_examples'])
      if (hasCodeExamplesTables) {
        appliedMigrations.set('013', {
          id: '013',
          applied_at: new Date().toISOString(),
          name: 'Code Examples Plugin',
          filename: '013_code_examples_plugin.sql'
        })
        await this.markMigrationApplied('013', 'Code Examples Plugin', '013_code_examples_plugin.sql')
      }
    }

    // Check if user management tables exist (migration 004)
    if (!appliedMigrations.has('004')) {
      const hasUserTables = await this.checkTablesExist(['api_tokens', 'workflow_history'])
      if (hasUserTables) {
        appliedMigrations.set('004', {
          id: '004',
          applied_at: new Date().toISOString(),
          name: 'User Management',
          filename: '004_stage6_user_management.sql'
        })
        await this.markMigrationApplied('004', 'User Management', '004_stage6_user_management.sql')
      }
    }

    // Check if plugin system tables exist (migration 006)
    if (!appliedMigrations.has('006')) {
      const hasPluginTables = await this.checkTablesExist(['plugins', 'plugin_hooks'])
      if (hasPluginTables) {
        appliedMigrations.set('006', {
          id: '006',
          applied_at: new Date().toISOString(),
          name: 'Plugin System',
          filename: '006_plugin_system.sql'
        })
        await this.markMigrationApplied('006', 'Plugin System', '006_plugin_system.sql')
      }
    }

    // Check if managed column exists (migration 011)
    // This handles both cases:
    // 1. Migration not marked as applied but column exists -> mark as applied
    // 2. Migration marked as applied but column doesn't exist -> remove from applied (will re-run)
    const hasManagedColumn = await this.checkColumnExists('collections', 'managed')
    if (!appliedMigrations.has('011') && hasManagedColumn) {
      appliedMigrations.set('011', {
        id: '011',
        applied_at: new Date().toISOString(),
        name: 'Config Managed Collections',
        filename: '011_config_managed_collections.sql'
      })
      await this.markMigrationApplied('011', 'Config Managed Collections', '011_config_managed_collections.sql')
    } else if (appliedMigrations.has('011') && !hasManagedColumn) {
      // Migration was marked as applied but column doesn't exist - remove it so it will re-run
      console.log('[Migration] Migration 011 marked as applied but managed column missing - will re-run')
      appliedMigrations.delete('011')
      await this.removeMigrationApplied('011')
    }

    // Check if system_logs table exists (migration 009)
    if (!appliedMigrations.has('009')) {
      const hasLoggingTables = await this.checkTablesExist(['system_logs', 'log_config'])
      if (hasLoggingTables) {
        appliedMigrations.set('009', {
          id: '009',
          applied_at: new Date().toISOString(),
          name: 'System Logging',
          filename: '009_system_logging.sql'
        })
        await this.markMigrationApplied('009', 'System Logging', '009_system_logging.sql')
      }
    }

    // Check if settings table exists (migration 018)
    if (!appliedMigrations.has('018')) {
      const hasSettingsTable = await this.checkTablesExist(['settings'])
      if (hasSettingsTable) {
        appliedMigrations.set('018', {
          id: '018',
          applied_at: new Date().toISOString(),
          name: 'Settings Table',
          filename: '018_settings_table.sql'
        })
        await this.markMigrationApplied('018', 'Settings Table', '018_settings_table.sql')
      }
    }

    // Check if forms tables exist (migration 029)
    // Migration 029 was reassigned between releases: older versions used it for "Ai Search Plugin",
    // newer versions use it for "Add Forms System". This handles the case where 029 is marked as
    // applied (from the old AI Search migration) but the forms tables don't actually exist.
    const hasFormsTables = await this.checkTablesExist(['forms', 'form_submissions', 'form_files'])
    if (!appliedMigrations.has('029') && hasFormsTables) {
      appliedMigrations.set('029', {
        id: '029',
        applied_at: new Date().toISOString(),
        name: 'Add Forms System',
        filename: '029_add_forms_system.sql'
      })
      await this.markMigrationApplied('029', 'Add Forms System', '029_add_forms_system.sql')
    } else if (appliedMigrations.has('029') && !hasFormsTables) {
      // Migration was marked as applied (possibly from old "Ai Search Plugin" migration)
      // but forms tables don't exist - remove it so the forms migration will re-run
      console.log('[Migration] Migration 029 marked as applied but forms tables missing - will re-run')
      appliedMigrations.delete('029')
      await this.removeMigrationApplied('029')
    }

    // Check if user_profiles table exists (migration 032)
    // Table may already exist from app-level migration (my-sonicjs-app/migrations/018_user_profiles.sql)
    if (!appliedMigrations.has('032')) {
      const hasUserProfilesTable = await this.checkTablesExist(['user_profiles'])
      if (hasUserProfilesTable) {
        appliedMigrations.set('032', {
          id: '032',
          applied_at: new Date().toISOString(),
          name: 'User Profiles',
          filename: '032_user_profiles.sql'
        })
        await this.markMigrationApplied('032', 'User Profiles', '032_user_profiles.sql')
      }
    }

    // Ensure user_profiles.data column exists (migration 035 is now a no-op).
    // Databases that ran the old 032 (without data column) need the column added.
    // Migration 035 was converted to a no-op to fix #771 (duplicate column error
    // on fresh installs), so we add the column here if it's missing.
    const hasUserProfilesTable = await this.checkTablesExist(['user_profiles'])
    if (hasUserProfilesTable) {
      const hasDataColumn = await this.checkColumnExists('user_profiles', 'data')
      if (!hasDataColumn) {
        try {
          await this.db.prepare(`ALTER TABLE user_profiles ADD COLUMN data TEXT DEFAULT '{}'`).run()
          console.log('[Migration] Added missing data column to user_profiles')
        } catch (error) {
          // Column may have been added concurrently; ignore duplicate column errors
          const msg = error instanceof Error ? error.message : String(error)
          if (!msg.includes('duplicate column name')) {
            console.error('[Migration] Failed to add data column to user_profiles:', msg)
          }
        }
      }
    }

    // Mark migration 035 as applied since it's now a no-op (column handled above)
    if (!appliedMigrations.has('035')) {
      const hasDataCol = hasUserProfilesTable && await this.checkColumnExists('user_profiles', 'data')
      if (hasDataCol) {
        appliedMigrations.set('035', {
          id: '035',
          applied_at: new Date().toISOString(),
          name: 'User Profiles Data Column',
          filename: '035_user_profiles_data_column.sql'
        })
        await this.markMigrationApplied('035', 'User Profiles Data Column', '035_user_profiles_data_column.sql')
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
    await this.initializeMigrationsTable()

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
   * Mark a migration as applied
   */
  async markMigrationApplied(migrationId: string, name: string, filename: string): Promise<void> {
    await this.initializeMigrationsTable()

    await this.db.prepare(
      'INSERT OR REPLACE INTO migrations (id, name, filename, applied_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)'
    ).bind(migrationId, name, filename).run()
  }

  /**
   * Remove a migration from the applied list (so it can be re-run)
   */
  async removeMigrationApplied(migrationId: string): Promise<void> {
    await this.initializeMigrationsTable()

    await this.db.prepare(
      'DELETE FROM migrations WHERE id = ?'
    ).bind(migrationId).run()
  }

  /**
   * Check if a specific migration has been applied
   */
  async isMigrationApplied(migrationId: string): Promise<boolean> {
    await this.initializeMigrationsTable()

    const result = await this.db.prepare(
      'SELECT COUNT(*) as count FROM migrations WHERE id = ?'
    ).bind(migrationId).first()

    return (result?.count as number) > 0
  }

  /**
   * Get the last applied migration
   */
  async getLastAppliedMigration(): Promise<Migration | null> {
    await this.initializeMigrationsTable()

    const result = await this.db.prepare(
      'SELECT id, name, filename, applied_at FROM migrations ORDER BY applied_at DESC LIMIT 1'
    ).first()

    if (!result) return null

    return {
      id: result.id as string,
      name: result.name as string,
      filename: result.filename as string,
      applied: true,
      appliedAt: result.applied_at as string
    }
  }

  /**
   * Run pending migrations
   */
  async runPendingMigrations(): Promise<{ success: boolean; message: string; applied: string[]; errors: string[] }> {
    await this.initializeMigrationsTable()

    const status = await this.getMigrationStatus()
    const pendingMigrations = status.migrations.filter(m => !m.applied)

    if (pendingMigrations.length === 0) {
      return {
        success: true,
        message: 'All migrations are up to date',
        applied: [],
        errors: []
      }
    }

    // Actually execute the migration files
    const applied: string[] = []
    const errors: string[] = []

    for (const migration of pendingMigrations) {
      try {
        console.log(`[Migration] Applying ${migration.id}: ${migration.name}`)
        await this.applyMigration(migration)
        await this.markMigrationApplied(migration.id, migration.name, migration.filename)
        applied.push(migration.id)
        console.log(`[Migration] Successfully applied ${migration.id}`)
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error)
        console.error(`[Migration] Failed to apply migration ${migration.id}:`, errorMessage)
        errors.push(`${migration.id}: ${errorMessage}`)
        // Continue with other migrations instead of stopping on first failure
        // This allows independent migrations to still be applied
      }
    }

    if (errors.length > 0 && applied.length === 0) {
      return {
        success: false,
        message: `Failed to apply migrations: ${errors.join('; ')}`,
        applied,
        errors
      }
    }

    return {
      success: true,
      message: applied.length > 0
        ? `Applied ${applied.length} migration(s)${errors.length > 0 ? ` (${errors.length} failed)` : ''}`
        : 'No migrations applied',
      applied,
      errors
    }
  }

  /**
   * Apply a specific migration
   */
  private async applyMigration(migration: Migration): Promise<void> {
    // Get the actual migration SQL from the bundle
    const migrationSQL = getMigrationSQLById(migration.id)

    if (migrationSQL === null) {
      throw new Error(`Migration SQL not found for ${migration.id}`)
    }

    if (migrationSQL.trim() === '') {
      console.log(`[Migration] Skipping empty migration ${migration.id}`)
      return
    }

    // Split SQL into individual statements, handling triggers properly
    const statements = this.splitSQLStatements(migrationSQL)

    for (const statement of statements) {
      if (statement.trim()) {
        try {
          await this.db.prepare(statement).run()
        } catch (error) {
          // Check if it's a "already exists" type error and skip it
          const errorMessage = error instanceof Error ? error.message : String(error)
          if (errorMessage.includes('already exists') ||
              errorMessage.includes('duplicate column name') ||
              errorMessage.includes('UNIQUE constraint failed')) {
            console.log(`[Migration] Skipping (already exists): ${statement.substring(0, 50)}...`)
            continue
          }
          console.error(`[Migration] Error executing statement: ${statement.substring(0, 100)}...`)
          throw error
        }
      }
    }
  }

  /**
   * Split SQL into statements, handling CREATE TRIGGER properly
   */
  private splitSQLStatements(sql: string): string[] {
    const statements: string[] = []
    let current = ''
    let inTrigger = false

    const lines = sql.split('\n')

    for (const line of lines) {
      const trimmed = line.trim()

      // Skip comments and empty lines
      if (trimmed.startsWith('--') || trimmed.length === 0) {
        continue
      }

      // Check if we're entering a trigger
      if (trimmed.toUpperCase().includes('CREATE TRIGGER')) {
        inTrigger = true
      }

      current += line + '\n'

      // Check if we're exiting a trigger
      if (inTrigger && trimmed.toUpperCase() === 'END;') {
        statements.push(current.trim())
        current = ''
        inTrigger = false
      }
      // Check for regular statement end (not in trigger)
      else if (!inTrigger && trimmed.endsWith(';')) {
        statements.push(current.trim())
        current = ''
      }
    }

    // Add any remaining statement
    if (current.trim()) {
      statements.push(current.trim())
    }

    return statements.filter(s => s.length > 0)
  }

  /**
   * Validate database schema
   */
  async validateSchema(): Promise<{ valid: boolean; issues: string[] }> {
    const issues: string[] = []

    // Basic table existence checks
    const requiredTables = [
      'users', 'content', 'collections', 'media'
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
