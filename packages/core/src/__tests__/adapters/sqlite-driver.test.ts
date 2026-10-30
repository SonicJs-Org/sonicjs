/**
 * Unit tests for the runtime SQLite driver (Tier 1 self-host adapter).
 * These run against better-sqlite3 (real SQL), not mocks.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createSqliteDriver } from '../../adapters/db/sqlite-driver'
import type { SqliteDriver } from '../../adapters/db/sqlite-driver'

let driver: SqliteDriver | undefined

afterEach(() => {
  driver?.close()
  driver = undefined
})

describe('createSqliteDriver — :memory: with auto-migrate', () => {
  it('creates a driver and applies migrations on first boot', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:' })
    // auth_user table must exist after migrations
    const result = await driver.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='auth_user'",
    ).first<{ name: string }>()
    expect(result?.name).toBe('auth_user')
  })

  it('documents table exists after migrations', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:' })
    const result = await driver.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='documents'",
    ).first<{ name: string }>()
    expect(result?.name).toBe('documents')
  })

  it('skips auto-migrate when autoMigrate=false', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:', autoMigrate: false })
    const result = await driver.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='auth_user'",
    ).first<{ name: string }>()
    expect(result).toBeNull()
  })
})

describe('D1Database interface — prepare / run / all / first', () => {
  it('prepare().run() inserts a row', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:', autoMigrate: false })
    await driver.prepare('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)').run()
    const result = await driver.prepare('INSERT INTO t (v) VALUES (?)').bind('hello').run()
    expect(result.success).toBe(true)
    expect(result.meta.changes).toBe(1)
  })

  it('prepare().all() returns rows', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:', autoMigrate: false })
    await driver.prepare('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)').run()
    await driver.prepare('INSERT INTO t (v) VALUES (?)').bind('a').run()
    await driver.prepare('INSERT INTO t (v) VALUES (?)').bind('b').run()
    const { results } = await driver.prepare('SELECT v FROM t ORDER BY v').all<{ v: string }>()
    expect(results).toEqual([{ v: 'a' }, { v: 'b' }])
  })

  it('prepare().first() returns one row', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:', autoMigrate: false })
    await driver.prepare('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)').run()
    await driver.prepare('INSERT INTO t (v) VALUES (?)').bind('only').run()
    const row = await driver.prepare('SELECT v FROM t').first<{ v: string }>()
    expect(row?.v).toBe('only')
  })

  it('prepare().first() returns null when no rows', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:', autoMigrate: false })
    await driver.prepare('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)').run()
    const row = await driver.prepare('SELECT v FROM t').first<{ v: string }>()
    expect(row).toBeNull()
  })

  it('first(colName) returns a scalar column', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:', autoMigrate: false })
    await driver.prepare('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)').run()
    await driver.prepare('INSERT INTO t (v) VALUES (?)').bind('scalar').run()
    const val = await driver.prepare('SELECT v FROM t').first<string>('v')
    expect(val).toBe('scalar')
  })
})

describe('D1Database interface — batch atomicity', () => {
  it('batch executes all statements atomically', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:', autoMigrate: false })
    await driver.prepare('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)').run()
    const s1 = driver.prepare('INSERT INTO t (v) VALUES (?)').bind('x')
    const s2 = driver.prepare('INSERT INTO t (v) VALUES (?)').bind('y')
    const results = await driver.batch([s1, s2])
    expect(results).toHaveLength(2)
    expect(results.every(r => r.success)).toBe(true)
    const { results: rows } = await driver.prepare('SELECT v FROM t ORDER BY v').all<{ v: string }>()
    expect(rows.map(r => r.v)).toEqual(['x', 'y'])
  })
})

describe('D1Database interface — exec', () => {
  it('exec runs raw SQL', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:', autoMigrate: false })
    const result = await driver.exec('CREATE TABLE exec_t (id INTEGER)')
    expect(result.count).toBe(1)
  })
})

describe('D1Database interface — dump', () => {
  it('dump returns an ArrayBuffer', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:', autoMigrate: false })
    await driver.prepare('CREATE TABLE t (id INTEGER PRIMARY KEY)').run()
    const buf = await driver.dump()
    expect(buf).toBeInstanceOf(ArrayBuffer)
    expect(buf.byteLength).toBeGreaterThan(0)
  })
})

describe('value coercion', () => {
  it('coerces undefined to null', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:', autoMigrate: false })
    await driver.prepare('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)').run()
    await driver.prepare('INSERT INTO t (v) VALUES (?)').bind(undefined).run()
    const row = await driver.prepare('SELECT v FROM t').first<{ v: string | null }>()
    expect(row?.v).toBeNull()
  })

  it('coerces boolean true to 1', async () => {
    driver = await createSqliteDriver({ dbPath: ':memory:', autoMigrate: false })
    await driver.prepare('CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER)').run()
    await driver.prepare('INSERT INTO t (v) VALUES (?)').bind(true).run()
    const row = await driver.prepare('SELECT v FROM t').first<{ v: number }>()
    expect(row?.v).toBe(1)
  })
})
