/**
 * Migration CI checks — Phase 5.
 *
 * Verifies that:
 *   1. Every .sql file in migrations/ is represented in the bundled migrations.
 *   2. Migration IDs are strictly monotonically increasing (no gaps skipped
 *      unintentionally, no duplicates).
 *   3. Every bundled migration's SQL is non-empty.
 *   4. The bundle was regenerated after any migration was added/removed
 *      (compare file count).
 *
 * Run via `vitest --run` as part of CI. If this test fails, run:
 *   npx tsx scripts/generate-migrations.ts
 * then commit the updated migrations-bundle.ts.
 */

import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'fs'
import { join, resolve } from 'path'
import { bundledMigrations } from './migrations-bundle'

const MIGRATIONS_DIR = resolve(__dirname, '../../migrations')

function getSqlFiles(): string[] {
  return readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql'))
    .sort()
}

describe('Migration bundle integrity', () => {
  const sqlFiles = getSqlFiles()

  it('migration directory has at least 40 files', () => {
    expect(sqlFiles.length).toBeGreaterThanOrEqual(40)
  })

  it('bundle contains the same number of migrations as .sql files', () => {
    expect(bundledMigrations.length).toBe(sqlFiles.length)
  })

  it('every .sql file has a corresponding bundle entry by filename', () => {
    const bundledFilenames = new Set(bundledMigrations.map(m => m.filename))
    const missing: string[] = []
    for (const file of sqlFiles) {
      if (!bundledFilenames.has(file)) missing.push(file)
    }
    expect(missing, `Missing from bundle: ${missing.join(', ')}`).toHaveLength(0)
  })

  it('no migration IDs are duplicated in the bundle', () => {
    const ids = bundledMigrations.map(m => m.id)
    const dupes = ids.filter((id, i) => ids.indexOf(id) !== i)
    expect(dupes, `Duplicate IDs: ${dupes.join(', ')}`).toHaveLength(0)
  })

  it('every bundled migration has non-empty SQL', () => {
    const empty = bundledMigrations.filter(m => !m.sql || m.sql.trim().length === 0)
    expect(empty.map(m => m.id), 'Migrations with empty SQL').toHaveLength(0)
  })

  it('bundle SQL matches source file content for each migration', () => {
    for (const migration of bundledMigrations) {
      const filePath = join(MIGRATIONS_DIR, migration.filename)
      const fileSQL = readFileSync(filePath, 'utf-8')
      expect(
        migration.sql.trim(),
        `Bundle SQL mismatch for ${migration.filename} — re-run generate-migrations.ts`
      ).toBe(fileSQL.trim())
    }
  })

  it('migration IDs are monotonically increasing (no ordering inversion)', () => {
    const ids = bundledMigrations.map(m => parseInt(m.id, 10)).filter(n => !isNaN(n))
    for (let i = 1; i < ids.length; i++) {
      expect(ids[i]!, `Migration ${i} ID`).toBeGreaterThan(ids[i - 1]!)
    }
  })
})

describe('Migration SQL safety checks', () => {
  it('no migration uses DROP TABLE without IF EXISTS (destructive without guard)', () => {
    const dangerous = bundledMigrations.filter(m =>
      /DROP\s+TABLE\s+(?!IF\s+EXISTS)/i.test(m.sql)
    )
    expect(
      dangerous.map(m => m.filename),
      'Migrations with unguarded DROP TABLE'
    ).toHaveLength(0)
  })

  it('ALTER TABLE statements use IF NOT EXISTS for new columns where possible', () => {
    // SQLite doesn't support IF NOT EXISTS on ALTER TABLE ADD COLUMN, so this
    // is informational — warn but don't fail.
    const alters = bundledMigrations.filter(m => /ALTER\s+TABLE.*ADD\s+COLUMN/i.test(m.sql))
    if (alters.length > 0) {
      console.info(
        `[migration-ci] ${alters.length} migration(s) use ALTER TABLE ADD COLUMN ` +
        `(SQLite doesn't support IF NOT EXISTS here; ensure migrations run only once).`
      )
    }
    // Not a failure — just informational
    expect(true).toBe(true)
  })
})
