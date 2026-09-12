/**
 * Enrolment must survive Better Auth's OWN insert.
 *
 * This test exists because the rest of the 2FA suite seeded `auth_two_factor` by hand — and
 * hand-written SQL supplies `created_at`/`updated_at`, which is exactly what BA does NOT.
 * `getAuthTables()` adds those two fields to the four CORE models only and spreads plugin
 * tables verbatim (@better-auth/core/dist/db/get-tables.mjs), and BA's twoFactor schema
 * declares just secret/backupCodes/userId/verified/failedVerificationCount/lockedUntil. So
 * `POST /two-factor/enable` inserts a row with no timestamps, drizzle emits explicit NULLs for
 * the absent NOT NULL columns, and SQLite rejects it — enrolment 500s for every user, and the
 * page reports it as a wrong password.
 *
 * Anything that drives this through real drizzle against the real migrations would have caught
 * it. PRAGMA column checks did not.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import Database from 'better-sqlite3'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { authTwoFactor } from '../../db/schema'

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '../../../migrations')

/**
 * The exact object Better Auth's adapter factory hands the drizzle adapter for
 * `create({ model: 'twoFactor' })` — every declared field, and nothing else.
 * Mirrors better-auth/dist/plugins/two-factor/index.mjs `enableTwoFactor`.
 */
const BA_CREATE_PAYLOAD = {
  id: 'tf-1',
  secret: 'encrypted-secret',
  backupCodes: 'encrypted-backup-codes',
  userId: 'user-1',
  verified: false,
  failedVerificationCount: 0,
  lockedUntil: null,
} as const

let sqlite: Database.Database
let db: ReturnType<typeof drizzle>

beforeEach(() => {
  sqlite = new Database(':memory:')
  sqlite.pragma('foreign_keys = OFF')
  for (const m of ['0001_core.sql', '0002_documents.sql', '0006_two_factor_lockout.sql']) {
    sqlite.exec(readFileSync(join(MIGRATIONS_DIR, m), 'utf8'))
  }
  db = drizzle(sqlite)
})

afterEach(() => sqlite.close())

describe('auth_two_factor accepts Better Auth\'s own insert', () => {
  it('inserts with only the fields BA declares — no timestamps supplied', () => {
    expect(() => db.insert(authTwoFactor).values(BA_CREATE_PAYLOAD).run()).not.toThrow()
  })

  it('fills created_at / updated_at itself, since BA never sends them', () => {
    const before = Date.now()
    db.insert(authTwoFactor).values(BA_CREATE_PAYLOAD).run()
    const row = sqlite
      .prepare(`SELECT created_at AS c, updated_at AS u FROM auth_two_factor WHERE id = 'tf-1'`)
      .get() as { c: number; u: number }
    expect(row.c).toBeGreaterThanOrEqual(before)
    expect(row.u).toBeGreaterThanOrEqual(before)
  })

  it('binds booleans through the column mode rather than handing SQLite a raw boolean', () => {
    // The drizzle adapter leaves BA's supportsBooleans at its `true` default, so BA passes a JS
    // boolean straight through. Without mode:'boolean' better-sqlite3 throws
    // "can only bind numbers, strings, bigints, buffers, and null".
    db.insert(authTwoFactor).values({ ...BA_CREATE_PAYLOAD, verified: true }).run()
    expect(
      (sqlite.prepare(`SELECT verified AS v FROM auth_two_factor WHERE id = 'tf-1'`).get() as { v: number }).v,
    ).toBe(1)
  })

  it('round-trips lockedUntil as a Date, which is what BA writes for a `date` field', () => {
    const when = new Date(Date.now() + 900_000)
    db.insert(authTwoFactor).values({ ...BA_CREATE_PAYLOAD, lockedUntil: when }).run()
    const stored = (
      sqlite.prepare(`SELECT locked_until AS l FROM auth_two_factor WHERE id = 'tf-1'`).get() as { l: number }
    ).l
    expect(stored).toBe(when.getTime())
    const [read] = db.select().from(authTwoFactor).all()
    expect(read!.lockedUntil).toBeInstanceOf(Date)
    expect(read!.lockedUntil!.getTime()).toBe(when.getTime())
  })

  it('names every column in the generated INSERT, so no NOT NULL column is left to a NULL bind', () => {
    const { sql } = db.insert(authTwoFactor).values(BA_CREATE_PAYLOAD).toSQL()
    for (const col of ['created_at', 'updated_at', 'failed_verification_count']) {
      expect(sql).toContain(`"${col}"`)
    }
  })
})
