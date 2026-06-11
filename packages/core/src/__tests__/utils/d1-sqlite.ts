import Database from 'better-sqlite3'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

// Real-SQLite test harness. Wraps better-sqlite3 in the subset of the D1Database
// interface the document services use (prepare/bind/run/all/first + batch) and applies
// the consolidated greenfield migrations so tests exercise the actual schema: generated columns, partial unique
// indexes, and db.batch atomicity — none of which the pure-mock suite can verify.
//
// Foreign keys are left OFF to mirror D1 (whose FK enforcement is not guaranteed); the
// services delete derived rows explicitly rather than relying on cascade.

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '../../../migrations')
const DOC_MIGRATIONS = ['0001_core.sql', '0002_documents.sql']

// better-sqlite3 only accepts numbers/strings/bigints/buffers/null. Coerce the values the
// services bind (undefined, booleans) the same way D1's binder tolerates them.
function normalize(v: unknown): number | string | bigint | Buffer | null {
  if (v === undefined || v === null) return null
  if (typeof v === 'boolean') return v ? 1 : 0
  return v as number | string | bigint | Buffer
}

class TestStatement {
  constructor(
    private sqlite: Database.Database,
    private sql: string,
    private binds: unknown[] = [],
  ) {}

  bind(...args: unknown[]): TestStatement {
    return new TestStatement(this.sqlite, this.sql, args.map(normalize))
  }

  async run() {
    const info = this.sqlite.prepare(this.sql).run(...(this.binds as never[]))
    return {
      success: true,
      meta: { changes: info.changes, last_row_id: Number(info.lastInsertRowid), rows_written: info.changes },
    }
  }

  async all<T = unknown>(): Promise<{ results: T[]; success: true; meta: Record<string, unknown> }> {
    const results = this.sqlite.prepare(this.sql).all(...(this.binds as never[])) as T[]
    return { results, success: true, meta: {} }
  }

  async first<T = unknown>(colName?: string): Promise<T | null> {
    const row = this.sqlite.prepare(this.sql).get(...(this.binds as never[])) as
      | Record<string, unknown>
      | undefined
    if (row == null) return null
    return (colName ? (row[colName] as T) : (row as unknown as T))
  }

  // Used by batch() to execute a write statement inside the shared transaction.
  execInBatch(): void {
    this.sqlite.prepare(this.sql).run(...(this.binds as never[]))
  }
}

export interface TestD1 {
  prepare(sql: string): TestStatement
  batch(statements: TestStatement[]): Promise<Array<{ success: boolean; results: unknown[] }>>
  /** Direct better-sqlite3 handle for test assertions (synchronous). */
  raw: Database.Database
  close(): void
}

export function createTestD1(): TestD1 {
  const sqlite = new Database(':memory:')
  // better-sqlite3 enables foreign_keys by default; D1 does NOT reliably enforce them, and the
  // services intentionally delete derived rows explicitly instead of relying on cascade. Turn them
  // OFF so the harness mirrors D1 behavior rather than testing a stricter contract than production.
  sqlite.pragma('foreign_keys = OFF')
  for (const m of DOC_MIGRATIONS) {
    sqlite.exec(readFileSync(join(MIGRATIONS_DIR, m), 'utf8'))
  }

  return {
    prepare(sql: string) {
      return new TestStatement(sqlite, sql)
    },
    async batch(statements: TestStatement[]) {
      // D1 batches are atomic + sequential under a single writer. Mirror with a transaction.
      const tx = sqlite.transaction((stmts: TestStatement[]) => {
        for (const s of stmts) s.execInBatch()
      })
      tx(statements)
      return statements.map(() => ({ success: true, results: [] }))
    },
    raw: sqlite,
    close() {
      sqlite.close()
    },
  }
}
