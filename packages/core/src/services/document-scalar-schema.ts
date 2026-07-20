import { D1Database } from '@cloudflare/workers-types'
import type { QueryableField } from '../schemas/document'

// Identifiers and JSON paths are interpolated into DDL (they cannot be bound), so
// they are format-guarded here. Source is trusted code config, not user input —
// this is defense-in-depth, mirroring document-repository.ts.
const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/

// Per-DB caches: eliminate repeated PRAGMA + CREATE INDEX round-trips across multiple
// ensureScalarSchema() calls during a bootstrap. Keyed by the binding object (WeakMap),
// NOT module-level: one bootstrap reuses one env.DB, so the intended dedup is fully
// preserved — while a DIFFERENT database gets a fresh snapshot instead of another DB's
// column set. (The module-level version broke every real-SQLite suite after the first
// test in a file: the next in-memory DB "already had" its q_* columns according to the
// cache, the ALTERs were skipped, and reads failed with "no such column".)
// The cached value is a single shared promise per DB so parallel callers during one
// bootstrap don't each fire their own PRAGMA batch.
const _docCaches = new WeakMap<D1Database, Promise<{ columns: Set<string>; indexes: Set<string> }>>()

/** Fetch (and cache per DB binding) column + index names on `documents` in one batch. */
function ensureDocumentsCaches(db: D1Database): Promise<{ columns: Set<string>; indexes: Set<string> }> {
  let cached = _docCaches.get(db)
  if (!cached) {
    cached = (async () => {
      try {
        const [colInfo, idxInfo] = await db.batch([
          db.prepare("SELECT name FROM pragma_table_xinfo('documents')"),
          db.prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='documents'"),
        ])
        return {
          columns: new Set((colInfo?.results ?? []).map((r: any) => r.name as string)),
          indexes: new Set((idxInfo?.results ?? []).map((r: any) => r.name as string)),
        }
      } catch {
        return { columns: new Set<string>(), indexes: new Set<string>() }
      }
    })()
    _docCaches.set(db, cached)
  }
  return cached
}

/** Map a queryable field's logical type to a SQLite column affinity. */
function affinity(type?: QueryableField['type']): 'TEXT' | 'INTEGER' | 'REAL' {
  if (type === 'number') return 'REAL'
  if (type === 'integer' || type === 'boolean' || type === 'date') return 'INTEGER'
  return 'TEXT'
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '')

/**
 * Authoritative generated-column name for a scalar field. An explicit `column`
 * always wins (back-compat with every existing type definition); otherwise it is
 * derived deterministically from the type id + field name. The repository reads
 * the same `column`/derivation when building filter SQL, so the two never drift.
 */
export function resolveColumn(typeId: string, f: QueryableField): string {
  if (f.column) return f.column
  const name = `q_${slug(typeId)}_${slug(f.name)}`
  return name.length <= 60 ? name : `q_${slug(typeId).slice(0, 20)}_${slug(f.name).slice(0, 20)}`
}

/**
 * Idempotently ensure the `documents` table has a VIRTUAL generated column and a
 * filter/sort index for each of a type's scalar queryable fields. Safe to call on
 * every registration and every bootstrap: existing columns/indexes are skipped,
 * and a concurrent add surfaces as a swallowed "duplicate column name".
 *
 * Facet and reference fields need no DDL (generic document_facets /
 * document_references tables), so they are ignored here.
 *
 * Returns the columns it actually created (empty when all already existed).
 */
export async function ensureScalarSchema(
  db: D1Database,
  typeId: string,
  fields: QueryableField[],
): Promise<string[]> {
  const scalars = fields.filter((f) => f.kind === 'scalar')
  if (scalars.length === 0) return []

  // Single batch PRAGMA per isolate — subsequent calls use cached Sets.
  const { columns: existing, indexes: knownIndexes } = await ensureDocumentsCaches(db)

  const added: string[] = []
  for (const f of scalars) {
    const col = resolveColumn(typeId, f)
    if (!SAFE_IDENTIFIER.test(col)) {
      console.error(`[scalar-schema] unsafe column name '${col}' for ${typeId}.${f.name} — skipped`)
      continue
    }
    const path = f.path ?? `$.${f.name}`
    if (path.includes("'")) {
      console.error(`[scalar-schema] unsafe json path for ${col} (${typeId}.${f.name}) — skipped`)
      continue
    }

    if (!existing.has(col)) {
      try {
        await db
          .prepare(`ALTER TABLE documents ADD COLUMN ${col} ${affinity(f.type)} AS (json_extract(data, '${path}')) VIRTUAL`)
          .run()
        added.push(col)
        existing.add(col)
        console.log(`[scalar-schema] added documents.${col} for type '${typeId}'`)
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error)
        if (msg.includes('duplicate column name')) {
          existing.add(col)
        } else {
          console.error(`[scalar-schema] failed to add documents.${col}:`, msg)
          continue
        }
      }
    }

    // One general index per column. Skip if already known to exist — avoids a D1
    // round-trip per column on every cold start.
    const idxName = `idx_${col}`
    if (!knownIndexes.has(idxName)) {
      try {
        await db
          .prepare(`CREATE INDEX IF NOT EXISTS ${idxName} ON documents(tenant_id, type_id, ${col}, updated_at DESC, id DESC)`)
          .run()
        knownIndexes.add(idxName)
      } catch (error) {
        console.error(`[scalar-schema] failed to create ${idxName}:`, error instanceof Error ? error.message : String(error))
      }
    }
  }
  return added
}
