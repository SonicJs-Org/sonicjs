/**
 * Runtime SQLite driver — D1Database-compatible adapter backed by better-sqlite3.
 *
 * Designed for Tier 1 self-hosted deployments (Docker, VPS, Node/Bun).
 * The Cloudflare Workers path never imports this file.
 *
 * Usage:
 *   import { createSqliteDriver } from '@sonicjs-cms/core/adapters'
 *   const db = await createSqliteDriver('./data/sonicjs.db')
 *   // Pass `db` anywhere SonicJS expects a D1Database binding.
 */

import Database from 'better-sqlite3'
import { readFileSync, mkdirSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// Walk up from the compiled file's location until we find a migrations/ directory.
// tsup flattens to dist/adapters.js (not dist/adapters/db/), so a fixed relative
// path would differ between source and compiled. Walking is reliable for both.
function migrationsDir(): string {
  let dir: string
  try {
    dir = dirname(fileURLToPath(import.meta.url))
  } catch {
    dir = __dirname
  }
  for (let i = 0; i < 6; i++) {
    const candidate = join(dir, 'migrations')
    if (existsSync(candidate)) return candidate
    dir = join(dir, '..')
  }
  throw new Error(`Cannot find migrations directory (searched from ${dirname(fileURLToPath(import.meta.url))})`)
}

const ORDERED_MIGRATIONS = ['0001_core.sql', '0002_documents.sql']

// D1-compatible value types accepted by better-sqlite3.
type BindValue = number | string | bigint | Buffer | null

function coerce(v: unknown): BindValue {
  if (v === undefined || v === null) return null
  if (typeof v === 'boolean') return v ? 1 : 0
  return v as BindValue
}

// ---------------------------------------------------------------------------
// D1Result / D1ExecResult shapes (mirrors @cloudflare/workers-types, locally
// defined so this file has zero runtime dep on that package).
// ---------------------------------------------------------------------------

interface D1Meta {
  duration: number
  size_after?: number
  rows_read: number
  rows_written: number
  last_row_id: number
  changed_db: boolean
  changes: number
}

interface D1Result<T = unknown> {
  results: T[]
  success: boolean
  meta: D1Meta
}

// ---------------------------------------------------------------------------
// SqliteStatement — wraps a prepared query with bound parameters.
// Implements the D1PreparedStatement interface.
// ---------------------------------------------------------------------------

class SqliteStatement {
  constructor(
    private readonly sqlite: Database.Database,
    private readonly sql: string,
    private readonly binds: BindValue[] = [],
  ) {}

  bind(...args: unknown[]): SqliteStatement {
    return new SqliteStatement(this.sqlite, this.sql, args.map(coerce))
  }

  async run(): Promise<D1Result<never>> {
    const t0 = Date.now()
    const stmt = this.sqlite.prepare(this.sql)
    const info = stmt.run(...this.binds)
    return {
      results: [],
      success: true,
      meta: {
        duration: Date.now() - t0,
        rows_read: 0,
        rows_written: info.changes,
        last_row_id: Number(info.lastInsertRowid),
        changed_db: info.changes > 0,
        changes: info.changes,
      },
    }
  }

  async all<T = unknown>(): Promise<D1Result<T>> {
    const t0 = Date.now()
    const results = this.sqlite.prepare(this.sql).all(...this.binds) as T[]
    return {
      results,
      success: true,
      meta: {
        duration: Date.now() - t0,
        rows_read: results.length,
        rows_written: 0,
        last_row_id: 0,
        changed_db: false,
        changes: 0,
      },
    }
  }

  async first<T = unknown>(colName?: string): Promise<T | null> {
    const row = this.sqlite.prepare(this.sql).get(...this.binds) as Record<string, unknown> | undefined
    if (row == null) return null
    return (colName ? (row[colName] as T) : (row as unknown as T))
  }

  // Returns rows as arrays (not objects) — used by drizzle-orm/d1 adapter.
  // Mirrors D1PreparedStatement.raw<T = unknown[]>(): Promise<T[]>
  async raw<T = unknown[]>(): Promise<T[]> {
    return this.sqlite.prepare(this.sql).raw().all(...this.binds) as T[]
  }

  // Used internally by batch() to execute within a shared transaction.
  execInBatch(): void {
    this.sqlite.prepare(this.sql).run(...this.binds)
  }
}

// ---------------------------------------------------------------------------
// SqliteDriver — the public D1Database-compatible runtime adapter.
// ---------------------------------------------------------------------------

export interface SqliteDriver {
  prepare(sql: string): SqliteStatement
  batch<T = unknown>(statements: SqliteStatement[]): Promise<Array<D1Result<T>>>
  exec(query: string): Promise<{ count: number; duration: number }>
  dump(): Promise<ArrayBuffer>
  /** Close the underlying database file handle (for graceful shutdown). */
  close(): void
  /** Path passed at creation time (`:memory:` for in-memory). */
  readonly path: string
}

function buildDriver(sqlite: Database.Database, path: string): SqliteDriver {
  // D1 does NOT reliably enforce foreign keys; services delete derived rows
  // explicitly.  Mirror that behaviour so self-host tests match prod.
  sqlite.pragma('foreign_keys = OFF')
  // WAL mode gives much better write concurrency on a persistent file.
  if (path !== ':memory:') {
    sqlite.pragma('journal_mode = WAL')
  }

  return {
    path,

    prepare(sql: string) {
      return new SqliteStatement(sqlite, sql)
    },

    async batch<T = unknown>(statements: SqliteStatement[]): Promise<Array<D1Result<T>>> {
      // D1 batches are atomic and sequential under a single writer.
      const tx = sqlite.transaction((stmts: SqliteStatement[]) => {
        for (const s of stmts) s.execInBatch()
      })
      tx(statements)
      return statements.map(() => ({
        results: [] as T[],
        success: true,
        meta: { duration: 0, rows_read: 0, rows_written: 0, last_row_id: 0, changed_db: true, changes: 0 },
      }))
    },

    async exec(query: string) {
      const t0 = Date.now()
      sqlite.exec(query)
      return { count: 1, duration: Date.now() - t0 }
    },

    async dump() {
      // better-sqlite3 serialize() returns a Buffer of the full DB.
      const buf: Buffer = sqlite.serialize()
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer
    },

    close() {
      sqlite.close()
    },
  }
}

// ---------------------------------------------------------------------------
// createSqliteDriver — public factory.
// ---------------------------------------------------------------------------

export interface SqliteDriverOptions {
  /**
   * Absolute or relative path to the SQLite database file, or `:memory:` for
   * an in-memory database.  Defaults to `:memory:`.
   */
  dbPath?: string
  /**
   * When true, applies the bundled SonicJS migrations (0001_core.sql,
   * 0002_documents.sql) before returning.  Defaults to true when the DB does
   * not yet contain the `auth_user` table (i.e. first boot).
   * Set to false if you manage migrations yourself via an external tool.
   */
  autoMigrate?: boolean
  /**
   * Directory that contains the *.sql migration files.  Defaults to the
   * migrations/ folder bundled with `@sonicjs-cms/core`.
   */
  migrationsPath?: string
}

/**
 * Create a D1Database-compatible SQLite driver for self-hosted deployments.
 *
 * ```ts
 * const db = await createSqliteDriver({ dbPath: './data/sonicjs.db' })
 * // db satisfies D1Database — pass it directly as c.env.DB
 * ```
 */
export async function createSqliteDriver(options: SqliteDriverOptions = {}): Promise<SqliteDriver> {
  const { dbPath = ':memory:', autoMigrate = true, migrationsPath } = options

  // Ensure parent directory exists for a file-based DB.
  if (dbPath !== ':memory:') {
    mkdirSync(dirname(dbPath), { recursive: true })
  }

  const sqlite = new Database(dbPath)
  const driver = buildDriver(sqlite, dbPath)

  if (autoMigrate && shouldRunMigrations(sqlite)) {
    applyMigrations(sqlite, migrationsPath ?? migrationsDir())
  }

  return driver
}

/** Returns true when the core schema hasn't been applied yet. */
function shouldRunMigrations(sqlite: Database.Database): boolean {
  try {
    const row = sqlite.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='auth_user'",
    ).get()
    return row == null
  } catch {
    return true
  }
}

function applyMigrations(sqlite: Database.Database, dir: string): void {
  for (const file of ORDERED_MIGRATIONS) {
    const sql = readFileSync(join(dir, file), 'utf8')
    sqlite.exec(sql)
  }
}
