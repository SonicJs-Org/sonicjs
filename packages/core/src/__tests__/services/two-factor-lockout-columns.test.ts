/**
 * Migration 0003 + the runtime self-heal for the `auth_two_factor` lockout columns.
 *
 * Without both columns, Better Auth's `/two-factor/enable` INSERT fails (BA fills schema
 * defaults on create, so the statement already names `failed_verification_count`) and enrolment
 * 500s. The self-heal exists for a DB that has 0001 but never got 0003.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import Database from 'better-sqlite3'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import type { D1Database } from '@cloudflare/workers-types'
import { MigrationService } from '../../services/migrations'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '../../../migrations')

function columnsOf(sqlite: Database.Database, table: string): string[] {
  return (sqlite.prepare(`PRAGMA table_xinfo('${table}')`).all() as Array<{ name: string }>).map(
    (r) => r.name,
  )
}

describe('migration 0003 (greenfield)', () => {
  let db: TestD1

  beforeEach(() => {
    db = createTestD1()
  })
  afterEach(() => db.close())

  it('gives auth_two_factor both lockout columns', () => {
    const cols = columnsOf(db.raw, 'auth_two_factor')
    expect(cols).toContain('failed_verification_count')
    expect(cols).toContain('locked_until')
  })

  it('defaults failed_verification_count to 0 and NOT NULL, so BA\'s +1 bump cannot go NULL', () => {
    db.raw
      .prepare(
        `INSERT INTO auth_two_factor (id, secret, backup_codes, user_id, created_at, updated_at)
         VALUES ('t','s','b','u', 0, 0)`,
      )
      .run()
    const row = db.raw
      .prepare(`SELECT failed_verification_count AS n, locked_until AS l FROM auth_two_factor`)
      .get() as { n: number; l: number | null }
    expect(row.n).toBe(0)
    expect(row.l).toBeNull()

    db.raw.prepare(`UPDATE auth_two_factor SET failed_verification_count = failed_verification_count + 1`).run()
    expect(
      (db.raw.prepare(`SELECT failed_verification_count AS n FROM auth_two_factor`).get() as { n: number }).n,
    ).toBe(1)
  })

  it('declares locked_until as INTEGER — drizzle timestamp_ms, not the kysely ISO string', () => {
    // The drizzle adapter leaves BA's supportsDates at true, so BA hands over a Date and the
    // drizzle column mode converts it. A TEXT column here would sort wrong on every comparison.
    const info = db.raw.prepare(`PRAGMA table_xinfo('auth_two_factor')`).all() as Array<{
      name: string
      type: string
    }>
    expect(info.find((c) => c.name === 'locked_until')?.type).toBe('INTEGER')
  })
})

describe('ensureSchemaCompatibility self-heal', () => {
  let sqlite: Database.Database

  /** A DB that ran 0001 + 0002 only — i.e. never got migration 0003. */
  function legacyDb(): D1Database {
    sqlite = new Database(':memory:')
    sqlite.pragma('foreign_keys = OFF')
    for (const m of ['0001_core.sql', '0002_documents.sql']) {
      sqlite.exec(readFileSync(join(MIGRATIONS_DIR, m), 'utf8'))
    }
    const stmt = (sql: string) => ({
      bind: (...binds: unknown[]) => ({
        first: async () => sqlite.prepare(sql).get(...(binds as never[])) ?? null,
        all: async () => ({ results: sqlite.prepare(sql).all(...(binds as never[])) }),
        run: async () => sqlite.prepare(sql).run(...(binds as never[])),
      }),
      first: async () => sqlite.prepare(sql).get() ?? null,
      all: async () => ({ results: sqlite.prepare(sql).all() }),
      run: async () => sqlite.prepare(sql).run(),
    })
    return { prepare: stmt } as unknown as D1Database
  }

  afterEach(() => {
    sqlite?.close()
    vi.restoreAllMocks()
  })

  it('adds both missing columns', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {})
    const db = legacyDb()
    expect(columnsOf(sqlite, 'auth_two_factor')).not.toContain('failed_verification_count')

    await new MigrationService(db).ensureSchemaCompatibility()

    const cols = columnsOf(sqlite, 'auth_two_factor')
    expect(cols).toContain('failed_verification_count')
    expect(cols).toContain('locked_until')
  })

  it('is idempotent — a second pass adds nothing and throws nothing', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {})
    const db = legacyDb()
    const service = new MigrationService(db)
    await service.ensureSchemaCompatibility()
    const after = columnsOf(sqlite, 'auth_two_factor')
    await expect(service.ensureSchemaCompatibility()).resolves.toBeUndefined()
    expect(columnsOf(sqlite, 'auth_two_factor')).toEqual(after)
  })

  it('does nothing when the table is absent, rather than failing bootstrap', async () => {
    const db = legacyDb()
    sqlite.exec('DROP TABLE auth_two_factor')
    await expect(new MigrationService(db).ensureSchemaCompatibility()).resolves.toBeUndefined()
  })
})
