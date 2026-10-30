/**
 * Better Auth ⇄ drizzle schema ⇄ migrated SQL parity.
 *
 * Better Auth 1.7.3+ checks its table model against the DRIZZLE schema at startup (and rejects
 * every auth request on a mismatch). It never looks at the SQL the migrations actually create,
 * so `db/schema.ts` and `migrations/*.sql` can drift apart without anything noticing until a
 * write fails in production. This closes that gap, using the table model read off a live
 * `createAuth()` instance — the real production options with every plugin — not a transcription.
 *
 * Two directions:
 *   1. every field Better Auth reads or writes maps to a drizzle property whose column exists
 *      in the migrated database;
 *   2. every NOT NULL column without a SQL default is either written by Better Auth or has a
 *      drizzle-side default — otherwise Better Auth's INSERT fails (the `updated_at` defect on
 *      the organization tables).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { getTableColumns, type Table } from 'drizzle-orm'
import { getAuthTables } from 'better-auth/db'
import { createAuth } from '../../auth/config'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'
import * as schema from '../../db/schema'
import type { Bindings } from '../../app'

let db: TestD1

beforeEach(() => {
  db = createTestD1()
})
afterEach(() => db.close())

// With CACHE_KV, sessions live in KV and `auth_session` drops out of Better Auth's model; without
// it (a deployment with no KV binding) sessions go to D1. The parity checks cover both.
const KV_MODES = [
  ['with CACHE_KV', true],
  ['without CACHE_KV', false],
] as const

function liveAuthTables(withKv = true) {
  const env = {
    DB: db,
    CACHE_KV: withKv ? { get: async () => null, put: async () => {}, delete: async () => {} } : undefined,
    BETTER_AUTH_SECRET: 'test-better-auth-secret-at-least-32-chars',
    BETTER_AUTH_URL: 'https://sonic.test',
  } as unknown as Bindings
  const auth = createAuth(env, undefined, 'https://sonic.test')
  return getAuthTables(auth.options as Parameters<typeof getAuthTables>[0])
}

/** drizzle tables by SQL table name — the same keys `config.ts` hands the adapter (modelName). */
function drizzleTablesByName(): Map<string, Table> {
  const out = new Map<string, Table>()
  for (const value of Object.values(schema)) {
    const name = (value as any)?.[Symbol.for('drizzle:Name')]
    if (typeof name === 'string') out.set(name, value as Table)
  }
  return out
}

function sqlColumns(table: string) {
  return db.raw.prepare(`PRAGMA table_info(${table})`).all() as {
    name: string
    notnull: number
    dflt_value: string | null
    pk: number
  }[]
}

describe('Better Auth schema parity', () => {
  it('reads the model from a live createAuth(), including plugin tables', () => {
    const models = Object.values(liveAuthTables()).map((t) => t.modelName)
    for (const m of ['auth_user', 'auth_account', 'auth_verification', 'auth_two_factor', 'auth_tenant', 'auth_tenant_member', 'auth_tenant_invitation']) {
      expect(models).toContain(m)
    }
  })

  it('keeps sessions in KV only — no auth_session rows (existing behaviour, made explicit)', () => {
    // With secondary storage configured and `session.storeSessionInDatabase` unset, Better Auth
    // drops the session table from its model and never writes `auth_session`. Revocation
    // (sign-out, role change, ban) is therefore subject to KV's eventual consistency across
    // locations. If this assertion starts failing, sessions moved to D1 — revisit that trade-off.
    const models = Object.values(liveAuthTables()).map((t) => t.modelName)
    expect(models).not.toContain('auth_session')
    expect(Object.values(liveAuthTables(false)).map((t) => t.modelName)).toContain('auth_session')
  })

  it.each(KV_MODES)('%s: every Better Auth field maps to a drizzle property whose column exists in the migrated DB', (_, withKv) => {
    const drizzle = drizzleTablesByName()
    const problems: string[] = []
    for (const t of Object.values(liveAuthTables(withKv))) {
      const table = drizzle.get(t.modelName)
      if (!table) { problems.push(`${t.modelName}: no drizzle table`); continue }
      const cols = getTableColumns(table)
      const sql = new Set(sqlColumns(t.modelName).map((c) => c.name))
      if (sql.size === 0) { problems.push(`${t.modelName}: table missing from migrations`); continue }
      for (const [field, attr] of Object.entries(t.fields)) {
        const prop = (attr as { fieldName?: string }).fieldName ?? field
        const col = cols[prop]
        if (!col) { problems.push(`${t.modelName}.${prop}: no drizzle property`); continue }
        if (!sql.has(col.name)) problems.push(`${t.modelName}.${prop} → column ${col.name} missing in SQL`)
      }
    }
    expect(problems).toEqual([])
  })

  it.each(KV_MODES)('%s: every NOT NULL column without a SQL default is written by Better Auth or defaulted by drizzle', (_, withKv) => {
    const drizzle = drizzleTablesByName()
    const problems: string[] = []
    for (const t of Object.values(liveAuthTables(withKv))) {
      const table = drizzle.get(t.modelName)
      if (!table) continue
      const cols = getTableColumns(table)
      const written = new Set(
        Object.entries(t.fields).map(([f, a]) => cols[(a as { fieldName?: string }).fieldName ?? f]?.name),
      )
      for (const c of sqlColumns(t.modelName)) {
        if (!c.notnull || c.dflt_value !== null || c.pk || c.name === 'id' || written.has(c.name)) continue
        const prop = Object.values(cols).find((col) => col.name === c.name)
        if (!prop?.hasDefault) problems.push(`${t.modelName}.${c.name}: NOT NULL, no default, never written`)
      }
    }
    expect(problems).toEqual([])
  })
})
