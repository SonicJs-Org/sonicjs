import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { D1Database } from '@cloudflare/workers-types'
import { MigrationService } from '../../services/migrations'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

describe('MigrationService tracking table (real SQLite)', () => {
  let db: TestD1
  let d1: D1Database

  beforeEach(() => {
    db = createTestD1()
    d1 = db as unknown as D1Database
    db.raw.exec(`
      CREATE TABLE d1_migrations (id INTEGER PRIMARY KEY, name TEXT, applied_at TEXT);
      CREATE TABLE custom_migration_history (id INTEGER PRIMARY KEY, NAME TEXT, APPLIED_AT TEXT);
      INSERT INTO d1_migrations VALUES (1, '0001_core.sql', '2026-01-01 00:00:00');
      INSERT INTO custom_migration_history VALUES (1, '0002_documents.sql', '2026-02-01 00:00:00');
      INSERT INTO custom_migration_history VALUES (2, '0003_session_org.sql', '2026-02-02 00:00:00');
      INSERT INTO custom_migration_history VALUES (3, '9000_application.sql', '2026-02-03 00:00:00');
    `)
  })

  afterEach(() => db.close())

  it('preserves the default D1 ledger when no options are supplied', async () => {
    const service = new MigrationService(d1)
    const status = await service.getMigrationStatus()
    expect(status).toMatchObject({ totalMigrations: 7, appliedMigrations: 1, pendingMigrations: 6, lastApplied: '2026-01-01 00:00:00' })
    expect(await service.isMigrationApplied('0001')).toBe(true)
    expect(await service.isMigrationApplied('0002')).toBe(false)
  })

  it('uses only the configured ledger, with stable field names and actual timestamps', async () => {
    const service = new MigrationService(d1, { tableName: 'custom_migration_history' })
    const before = db.raw.serialize()
    const status = await service.getMigrationStatus()
    expect(status).toMatchObject({ totalMigrations: 7, appliedMigrations: 2, pendingMigrations: 5, lastApplied: '2026-02-02 00:00:00' })
    expect(status.migrations.find(m => m.id === '0002')).toMatchObject({ applied: true, appliedAt: '2026-02-01 00:00:00' })
    expect(await service.isMigrationApplied('0001')).toBe(false)
    expect(await service.isMigrationApplied('0003')).toBe(true)
    expect(status.migrations.some(m => m.id === '9000')).toBe(false)
    expect(db.raw.serialize()).toEqual(before)
  })

  it('does not fall back to another ledger or create a missing configured table', async () => {
    const before = db.raw.serialize()
    const status = await new MigrationService(d1, { tableName: 'missing_history' }).getMigrationStatus()
    expect(status).toMatchObject({ appliedMigrations: 0, pendingMigrations: 7 })
    expect(status.lastApplied).toBeUndefined()
    expect(db.raw.serialize()).toEqual(before)
  })

  it('copies the selected table at construction instead of retaining mutable options', async () => {
    const options = { tableName: 'custom_migration_history' }
    const service = new MigrationService(d1, options)
    options.tableName = 'd1_migrations'
    expect((await service.getMigrationStatus()).appliedMigrations).toBe(2)
  })

  it('quotes accepted identifiers, including SQL keywords', async () => {
    db.raw.exec(`CREATE TABLE "select" (name TEXT, applied_at TEXT); INSERT INTO "select" VALUES ('0001_core.sql', '2026-03-01');`)
    const status = await new MigrationService(d1, { tableName: 'select' }).getMigrationStatus()
    expect(status).toMatchObject({ appliedMigrations: 1, lastApplied: '2026-03-01' })
  })

  it.each(['', ' ledger', 'ledger ', 'custom-history', 'main.ledger', 'ledger; DROP TABLE documents', 'ledger"', 'ledger\n', 'ledger\u0000'])('rejects invalid identifier %j before preparing SQL', tableName => {
    const prepare = vi.spyOn(db, 'prepare')
    expect(() => new MigrationService(d1, { tableName })).toThrow(/migration.*table/i)
    expect(prepare).not.toHaveBeenCalled()
  })

  it.each([null, 42, {}, ['ledger']])('rejects non-string identifier %j at the runtime boundary', tableName => {
    expect(() => new MigrationService(d1, { tableName: tableName as never })).toThrow(/migration.*table/i)
  })
})
