/**
 * views-document-repository.ts — the Views plugin's read-only query surface over `documents`.
 *
 * Ported from the origin's `DocumentRepository` (the doc-model convergence engine), TRIMMED to
 * exactly what Views executes — getType / list / count / listKeyset + the shared buildWhere /
 * buildFilterClause — and REMAPPED for this codebase's native document semantics. Do NOT merge
 * this with `services/documents.ts`'s `DocumentRepository`: that one is a q_*-equality list
 * API; this one is the Views filter engine (operators, OR/AND groups, `json_extract` fallback,
 * keyset cursors). Read-only by design — Views never writes documents.
 *
 * The two load-bearing remaps vs the origin implementation (the C2/C3 corrections):
 *
 *   1. CURRENT-ROW SCOPES (C2). the origin's projection stores ONE row per doc, so its admin
 *      "all" scope was a bare `deleted_at IS NULL`. Here `documents` holds every historical
 *      version in-table, so that predicate would sweep old versions in and double-count
 *      draft+published roots. Scopes therefore read the CURRENT row:
 *        'all'       → is_current_draft = 1 AND deleted_at IS NULL   (canonical current-row read)
 *        'draft'     → is_current_draft = 1 AND deleted_at IS NULL
 *        'published' → is_published = 1 AND deleted_at IS NULL        (hits idx_documents_published_cursor)
 *        'deleted'   → is_current_draft = 1 AND deleted_at IS NOT NULL (softDelete keeps axis flags)
 *
 *   2. STRUCTURAL COLUMNS (C3). the origin's projection spread the whole content row into
 *      `data`, so `json_extract(data,'$.status')` etc. worked there. Here `data` holds only
 *      the user-authored fields; id/slug/title/status/timestamps live as real columns. Any
 *      filter/sort on a structural field maps to the NATIVE column — never json_extract.
 */

import type { D1Database } from '@cloudflare/workers-types'

/** Minimal async SQL seam (D1 today; sqlite in tests). Read-only — Views never writes. */
export interface SqlExecutor {
  all<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<T[]>
}

/** D1 adapter: wire to env.DB. */
export function d1Executor(db: D1Database): SqlExecutor {
  return {
    all: async <T = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<T[]> => {
      const stmt = params.length ? db.prepare(sql).bind(...params) : db.prepare(sql)
      const { results } = await stmt.all<T extends Record<string, unknown> ? T : Record<string, unknown>>()
      return results as T[]
    },
  }
}

// Mirrors the queryableFields config stored in document_types.queryable_fields.
export interface QueryableField {
  name: string
  path?: string
  kind: 'scalar' | 'facet' | 'reference'
  type?: 'text' | 'number' | 'integer' | 'boolean' | 'date'
  column?: string // generated column name (q_*), once promoted — index-served when present
  refStrength?: 'strong' | 'weak'
}

export interface DocumentType {
  id: string
  name: string
  queryableFields: QueryableField[]
}

/** One filter clause. `like` takes a FULL pre-built pattern; `in` a non-empty array;
 *  `between` a [low, high] pair emitting one atomic parenthesized fragment. */
export interface DocumentFilter {
  field: string
  op?: '=' | '!=' | '>' | '>=' | '<' | '<=' | 'is null' | 'is not null' | 'like' | 'in' | 'between'
  value?: unknown
}

export interface DocumentListSpec {
  typeId: string
  tenantId?: string
  filters?: DocumentFilter[]
  /** OR/AND filter groups: each group is `(rule <match> rule …)`, AND-ed with everything else —
   *  the read-scope stays a mandatory top-level AND, so no group can re-admit a filtered row. */
  groups?: Array<{ match: 'and' | 'or'; filters: DocumentFilter[] }>
  sort?: Array<{ field: string; dir?: 'asc' | 'desc' }>
  limit?: number
  offset?: number
  /** Which rows to read; default 'published'. See the C2 header note — all scopes are
   *  current-row reads on this substrate. */
  scope?: 'published' | 'draft' | 'all' | 'deleted'
}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/
const ident = (s: string, what: string): string => {
  if (!IDENT.test(s)) throw new Error(`Unsafe ${what}: ${JSON.stringify(s)}`)
  return s
}

/**
 * The `documents` columns Views may filter/sort on natively (C3). Everything else resolves
 * through queryableFields (`column` promotion or `json_extract(data, path)`).
 * `status` IS native here (unlike the origin implementation, where the projection carried it in
 * `data`) — the provider still fast-paths `status _eq 'published'`/`'deleted'` onto the
 * axis scopes; every other status shape binds this column directly.
 */
export const STRUCTURAL_COLUMNS: ReadonlySet<string> = new Set([
  'id', 'root_id', 'slug', 'path', 'title', 'status', 'sort_order',
  'published_at', 'created_at', 'updated_at', 'created_by', 'updated_by',
])

/** Scope → SQL predicate (C2: every scope is a current-row read; no version sweep). */
function scopePredicate(scope: DocumentListSpec['scope']): string {
  switch (scope) {
    case 'draft':
    case 'all':
      return 'is_current_draft = 1 AND deleted_at IS NULL'
    case 'deleted':
      return 'is_current_draft = 1 AND deleted_at IS NOT NULL'
    default:
      return 'is_published = 1 AND deleted_at IS NULL'
  }
}

export class ViewsDocumentRepository {
  constructor(
    private readonly exec: SqlExecutor,
    private readonly tenantId: string = 'default',
  ) {}

  /** Type loader for the provider — `document_types` by id (the registry id, == name for
   *  code-defined collections). NOTE: `document_types` is NOT tenant-scoped on this schema
   *  (only `documents` carries `tenant_id`). */
  async getType(typeId: string): Promise<DocumentType | null> {
    const rows = await this.exec.all<{ id: string; name: string; queryable_fields: string }>(
      `SELECT id, name, queryable_fields FROM document_types WHERE id = ?`,
      [typeId],
    )
    const row = rows[0]
    if (!row) return null
    let queryableFields: QueryableField[] = []
    try {
      const parsed: unknown = JSON.parse(row.queryable_fields || '[]')
      if (Array.isArray(parsed)) queryableFields = parsed as QueryableField[]
    } catch {
      queryableFields = []
    }
    return { id: row.id, name: row.name, queryableFields }
  }

  async list(type: DocumentType, spec: DocumentListSpec): Promise<Record<string, unknown>[]> {
    const byName = new Map(type.queryableFields.map((f) => [f.name, f]))
    const { clauses, params } = this.buildWhere(type, spec)

    const order: string[] = []
    for (const s of spec.sort ?? []) {
      const dir = s.dir === 'desc' ? 'DESC' : 'ASC'
      if (STRUCTURAL_COLUMNS.has(s.field)) {
        order.push(`${ident(s.field, 'sort column')} ${dir}`) // native column (C3)
        continue
      }
      const field = byName.get(s.field)
      if (field?.column) order.push(`${ident(field.column, 'column')} ${dir}`)
      else {
        order.push(`json_extract(data, ?) ${dir}`)
        params.push(field?.path ?? `$.${s.field}`)
      }
    }

    let sql = `SELECT * FROM documents WHERE ${clauses.join(' AND ')}`
    if (order.length) sql += ` ORDER BY ${order.join(', ')}`
    sql += ` LIMIT ? OFFSET ?`
    params.push(Math.min(spec.limit ?? 50, 200), spec.offset ?? 0)

    return this.exec.all(sql, params)
  }

  async count(type: DocumentType, spec: DocumentListSpec): Promise<number> {
    const { clauses, params } = this.buildWhere(type, spec)
    const sql = `SELECT COUNT(*) AS n FROM documents WHERE ${clauses.join(' AND ')}`
    const rows = await this.exec.all<{ n: number }>(sql, params)
    return Number(rows[0]?.n ?? 0)
  }

  /** Keyset (cursor) list. Sort keys MUST be structural (`updated_at`/`created_at`/`id`) so the
   *  published-cursor index serves them; N keys + `id` tiebreaker; LIMIT+1 detects a next page. */
  private static readonly CURSOR_FIELDS = new Set<string>(['updated_at', 'created_at', 'id'])
  async listKeyset(
    type: DocumentType,
    spec: DocumentListSpec,
    cursor: {
      keys: Array<{ field: string; dir: 'asc' | 'desc' }>
      position?: { values: unknown[]; id: string }
      limit: number
    },
  ): Promise<Record<string, unknown>[]> {
    for (const k of cursor.keys) {
      if (!ViewsDocumentRepository.CURSOR_FIELDS.has(k.field)) {
        throw new Error(`cursor field "${k.field}" is not a supported structural sort column`)
      }
    }
    const idDir: 'asc' | 'desc' = cursor.keys.length > 0 ? cursor.keys[cursor.keys.length - 1]!.dir : 'asc'
    const { clauses, params } = this.buildWhere(type, spec)
    if (cursor.position) {
      clauses.push(this.keysetClause(cursor.keys, idDir, cursor.position, params))
    }
    const order = cursor.keys.map((k) => `${k.field} ${k.dir === 'asc' ? 'ASC' : 'DESC'}`)
    order.push(`id ${idDir === 'asc' ? 'ASC' : 'DESC'}`)
    const sql = `SELECT * FROM documents WHERE ${clauses.join(' AND ')} ORDER BY ${order.join(', ')} LIMIT ?`
    params.push(cursor.limit + 1)
    return this.exec.all(sql, params)
  }

  /** Shared WHERE: tenant + type + scope + filters + groups. Params in exact clause order —
   *  a json_extract filter pushes its path immediately before its value. */
  private buildWhere(type: DocumentType, spec: DocumentListSpec): { clauses: string[]; params: unknown[] } {
    const byName = new Map(type.queryableFields.map((f) => [f.name, f]))
    const clauses: string[] = ['tenant_id = ?', 'type_id = ?']
    const params: unknown[] = [spec.tenantId ?? this.tenantId, type.id]

    clauses.push(scopePredicate(spec.scope))

    for (const f of spec.filters ?? []) {
      const c = this.buildFilterClause(byName, f)
      clauses.push(c.sql)
      params.push(...c.params)
    }

    for (const g of spec.groups ?? []) {
      if (g.filters.length === 0) continue // never emit `()`
      const parts = g.filters.map((f) => this.buildFilterClause(byName, f))
      const joiner = g.match === 'or' ? ' OR ' : ' AND '
      clauses.push(`(${parts.map((p) => p.sql).join(joiner)})`)
      for (const p of parts) params.push(...p.params)
    }
    return { clauses, params }
  }

  /** ONE self-contained boolean fragment + params IN TEXT ORDER. Structural fields (C3) get the
   *  native column; promoted queryableFields get their q_* column; everything else json_extract. */
  private buildFilterClause(
    byName: Map<string, QueryableField>,
    f: DocumentFilter,
  ): { sql: string; params: unknown[] } {
    const op = f.op ?? '='
    const field = byName.get(f.field)
    const colExpr = STRUCTURAL_COLUMNS.has(f.field)
      ? ident(f.field, 'column') // native documents column (C3)
      : field?.column
        ? ident(field.column, 'column') // promoted q_* generated column (index-served)
        : null
    const path = field?.path ?? `$.${f.field}` // inline json_extract fallback

    if (op === 'is null' || op === 'is not null') {
      const sqlOp = op === 'is null' ? 'IS NULL' : 'IS NOT NULL'
      return colExpr
        ? { sql: `${colExpr} ${sqlOp}`, params: [] }
        : { sql: `json_extract(data, ?) ${sqlOp}`, params: [path] }
    }
    if (op === 'between') {
      const v = f.value
      if (!Array.isArray(v) || v.length !== 2) {
        throw new Error(`'between' requires a [low, high] array (got ${JSON.stringify(f.value)})`)
      }
      const [low, high] = v
      return colExpr
        ? { sql: `(${colExpr} >= ? AND ${colExpr} <= ?)`, params: [low, high] }
        : { sql: `(json_extract(data, ?) >= ? AND json_extract(data, ?) <= ?)`, params: [path, low, path, high] }
    }
    // LIKE: value is the FULL pre-built pattern (escapeLike upstream); ESCAPE makes \% \_ \\ literal.
    if (op === 'like') {
      return colExpr
        ? { sql: `${colExpr} LIKE ? ESCAPE '\\'`, params: [f.value] }
        : { sql: `json_extract(data, ?) LIKE ? ESCAPE '\\'`, params: [path, f.value] }
    }
    if (op === 'in') {
      const values = f.value
      if (!Array.isArray(values) || values.length === 0) {
        throw new Error(`'in' requires a non-empty array (got ${JSON.stringify(f.value)})`)
      }
      const placeholders = values.map(() => '?').join(', ')
      return colExpr
        ? { sql: `${colExpr} IN (${placeholders})`, params: [...values] }
        : { sql: `json_extract(data, ?) IN (${placeholders})`, params: [path, ...values] }
    }
    if (!['=', '!=', '>', '>=', '<', '<='].includes(op)) throw new Error(`Bad op: ${op}`)
    return colExpr
      ? { sql: `${colExpr} ${op} ?`, params: [f.value] }
      : { sql: `json_extract(data, ?) ${op} ?`, params: [path, f.value] }
  }

  /** The lexicographic keyset predicate (structural, CURSOR_FIELDS-validated identifiers). */
  private keysetClause(
    keys: Array<{ field: string; dir: 'asc' | 'desc' }>,
    idDir: 'asc' | 'desc',
    position: { values: unknown[]; id: string },
    params: unknown[],
  ): string {
    const cmp = (dir: 'asc' | 'desc'): string => (dir === 'asc' ? '>' : '<')
    const disjuncts: string[] = []
    for (let r = 0; r < keys.length; r++) {
      const terms: string[] = []
      for (let p = 0; p < r; p++) {
        terms.push(`${keys[p]!.field} = ?`)
        params.push(position.values[p])
      }
      terms.push(`${keys[r]!.field} ${cmp(keys[r]!.dir)} ?`)
      params.push(position.values[r])
      disjuncts.push(terms.length > 1 ? `(${terms.join(' AND ')})` : terms[0]!)
    }
    const idTerms: string[] = []
    for (let p = 0; p < keys.length; p++) {
      idTerms.push(`${keys[p]!.field} = ?`)
      params.push(position.values[p])
    }
    idTerms.push(`id ${cmp(idDir)} ?`)
    params.push(position.id)
    disjuncts.push(`(${idTerms.join(' AND ')})`)
    return `(${disjuncts.join(' OR ')})`
  }
}
