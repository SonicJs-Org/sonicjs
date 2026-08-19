/**
 * document-query-provider.ts — the doc-model impl of `ViewQueryProvider`, and on this
 * codebase the ONLY provider (collection content lives in `documents`; there are no
 * per-collection tables and therefore no fallback provider — the port's C4).
 *
 * Maps a fully-resolved `ViewQueryRequest` onto a `ViewsDocumentRepository` query
 * (native structural columns + promoted `q_*` columns + `json_extract(data, path)`
 * fallback) and returns `{ rows, total }`.
 *
 * SUPPORTED: `_eq _neq _gt _gte _lt _lte _between _null` scalar filters; `_contains
 * _starts _in` on TEXT fields; OR/AND groups; sort; offset + keyset pagination; the full
 * status axis (`published`/`deleted` fast-path onto the read scopes; any other status
 * shape binds the native `status` column — including inside groups, which is expressible
 * here because status is a real column, not a projection field). UNSUPPORTED shapes fail
 * LOUD via `DocModelUnsupportedError` — the routes surface a 400, never silently-wrong
 * rows (there is no c_* fallback to absorb them).
 */
import {
  ViewsDocumentRepository,
  STRUCTURAL_COLUMNS,
  type DocumentListSpec,
} from './views-document-repository'
import type { ViewQueryProvider, ViewQueryRequest, ViewQueryResult } from './query-provider'
import type { EnrichedColumn, FilterRule, HandlerFamily } from './types'
import { resolveHandlerFamily } from './column-resolver'
import { DocumentPermissionsService } from '../../../../services/document-permissions'
import type { PrincipalRef } from '../../../../schemas/document'
// Reuse the EXACT c_* value-shaping the filter grammar defines: LIKE escaping, the shared
// _in/_between STRING parsers, AND the numeric/date value coercion. The coercion is load-bearing —
// `json_extract(data,'$.f')` returns a TYPED value (a boolean is `1`, a number is a number), so a
// raw string filter value ('true', '100' — how saved configs AND runtime query params both arrive)
// would silently mis-match without it (a typed-value coercion bug in the origin; ported here).
import {
  escapeLike,
  parseInValues,
  parseBetweenValues,
  coerceNumericValue,
  coerceDateValue,
} from './filter-handlers'
import { encodeCursor } from './cursor'

/** Raised when a view config uses an operator/shape the document model can't express. Loud by
 *  design — the routes map it to a 400 with the message (no fallback substrate exists). */
export class DocModelUnsupportedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DocModelUnsupportedError'
  }
}

type DocScalarOp = '=' | '!=' | '>' | '>=' | '<' | '<='
type DocFilter = NonNullable<DocumentListSpec['filters']>[number]

// Views operator → scalar op (the directly-expressible subset).
const SCALAR_OP: Partial<Record<FilterRule['operator'], DocScalarOp>> = {
  _eq: '=',
  _neq: '!=',
  _gt: '>',
  _gte: '>=',
  _lt: '<',
  _lte: '<=',
}

// The anonymous public principal — the only caller identity on the public API/embed surfaces.
const PUBLIC_PRINCIPAL: PrincipalRef[] = [{ type: 'public', id: '*' }]

export class DocumentQueryProvider implements ViewQueryProvider {
  readonly kind = 'document' as const
  constructor(
    private readonly repo: ViewsDocumentRepository,
    // Optional so unit tests can construct the provider without ACL wiring; the real
    // per-request wiring (createViewService) always supplies it, so anonymous reads honor
    // per-document deny overrides.
    private readonly permissions?: DocumentPermissionsService,
    private readonly tenantId: string = 'default',
  ) {}

  /** Per-document "deny wins" filter for anonymous reads. The collection-grant gate covers the
   *  type level; this drops any fetched row whose root carries a public `read` deny override.
   *  One query (deny rows are rare); mirrors the core public content API, which filters the page
   *  the same way (so `total` may over-count by the number of denied rows on the page — an
   *  accepted, platform-consistent imprecision that only manifests when deny overrides exist). */
  private async filterDeniedRoots(rows: Record<string, unknown>[]): Promise<Record<string, unknown>[]> {
    if (!this.permissions || rows.length === 0) return rows
    const denied = await this.permissions.listDeniedRoots(PUBLIC_PRINCIPAL, 'read', this.tenantId)
    if (denied.size === 0) return rows
    return rows.filter((r) => !denied.has(String(r['root_id'])))
  }

  async query(req: ViewQueryRequest): Promise<ViewQueryResult> {
    const type = await this.repo.getType(req.collectionId)
    if (!type) {
      throw new DocModelUnsupportedError(
        `No document_type provisioned for collection "${req.collectionId}"`,
      )
    }

    const spec = this.toSpec(req)

    // Keyset (cursor) mode — structural-column sort, no COUNT; capture the cursor from the FULL
    // documents row BEFORE projectRow strips it to the whitelist.
    if (req.cursor) {
      const limit = req.limit > 0 ? Math.min(req.limit, req.pagination.maxLimit) : req.pagination.defaultLimit
      const cursorKeys = req.cursor.keys
      const docRows = await this.repo.listKeyset(type, spec, {
        keys: cursorKeys,
        position: req.cursor.position,
        limit,
      })
      const hasMore = docRows.length > limit
      const pageDocs = hasMore ? docRows.slice(0, limit) : docRows
      const lastDoc = pageDocs[pageDocs.length - 1]
      const nextCursor =
        hasMore && lastDoc
          ? encodeCursor({
              values: cursorKeys.map((k) => lastDoc[k.field]),
              id: String(lastDoc['id']),
              keys: cursorKeys.map((k) => `${k.field}:${k.dir}`),
            })
          : null
      const visibleCursor = this.visibleColumns(req)
      // Per-doc deny filter runs AFTER the cursor is derived (the cursor is a position, valid
      // regardless of ACL; the next page re-filters from it).
      const filteredCursorDocs = req.anonymousPublic ? await this.filterDeniedRoots(pageDocs) : pageDocs
      const rows = filteredCursorDocs.map((doc) => this.projectRow(doc, visibleCursor))
      return { rows, total: 0, nextCursor }
    }

    const [docRows, total] = await Promise.all([
      this.repo.list(type, spec),
      this.repo.count(type, spec),
    ])

    const filteredDocs = req.anonymousPublic ? await this.filterDeniedRoots(docRows) : docRows
    const visible = this.visibleColumns(req)
    const rows = filteredDocs.map((doc) => this.projectRow(doc, visible))
    return { rows, total }
  }

  /** Map the resolved request onto a `DocumentListSpec`, or throw loud on an unsupported op. */
  private toSpec(req: ViewQueryRequest): DocumentListSpec {
    const filters: DocFilter[] = []
    // Default 'all' = the current-row admin read (is_current_draft=1, non-deleted — C2).
    // Public surfaces ALWAYS force `status _eq 'published'`, so they hit the axis branch below.
    let scope: DocumentListSpec['scope'] = 'all'

    // The resolved column carries what BOTH the family guard (LIKE/IN text-only) AND the value
    // coercion (numeric/date) need — c_* coerces per family, so the doc path binds the SAME column.
    const colByName = new Map<string, EnrichedColumn>(
      req.columns.map((c) => [c.name, c]),
    )

    for (const rule of req.filters) {
      if (rule.field === 'status' && rule.operator === '_eq') {
        if (rule.value === 'published') {
          // The indexed publish axis (is_published = 1 ⇔ status = 'published' on this
          // write path) — keeps public reads on idx_documents_published_cursor.
          scope = 'published'
          continue
        }
        if (rule.value === 'deleted') {
          // Soft-deleted current rows (deleted_at set; axis flags retained by softDelete).
          // Expressible HERE because deleted rows keep their document row — the origin
          // implementation had to reject this (its projection removes deleted docs).
          scope = 'deleted'
          continue
        }
        // draft / archived / … → the native status column at the 'all' current-row scope.
        filters.push({ field: 'status', op: '=', value: rule.value })
        continue
      }
      // Any other status shape (_neq/_in/…) binds the native status column via the generic
      // path below — correct on this substrate ('deleted' as a VALUE simply matches nothing;
      // deletion is the deleted_at axis, not a status value).
      this.appendScalar(filters, rule, colByName.get(rule.field))
    }

    // OR/AND groups: each rule mapped by the SAME appendScalar. A status rule inside a group
    // binds the native column — expressible here (unlike the projection substrate); public
    // surfaces strip status from groups upstream (ViewService 8b), so the forced published
    // axis can never be OR-ed around.
    const groups: NonNullable<DocumentListSpec['groups']> = []
    for (const g of req.groups ?? []) {
      const groupFilters: DocFilter[] = []
      for (const rule of g.rules) {
        this.appendScalar(groupFilters, rule, colByName.get(rule.field))
      }
      if (groupFilters.length > 0) groups.push({ match: g.match, filters: groupFilters })
    }

    // Effective limit EXACTLY as the offset engine expects: a request without an explicit
    // limit carries limit=0, which defaults to pagination.defaultLimit.
    const limit = req.limit > 0
      ? Math.min(req.limit, req.pagination.maxLimit)
      : req.pagination.defaultLimit

    return {
      typeId: req.collectionId,
      filters,
      groups: groups.length > 0 ? groups : undefined,
      sort: req.sort.map((s) => ({ field: s.field, dir: s.direction })),
      limit,
      offset: Math.max(0, (req.page - 1) * limit),
      scope,
    }
  }

  private appendScalar(filters: DocFilter[], rule: FilterRule, col: EnrichedColumn | undefined): void {
    const op = rule.operator
    const family = col ? resolveHandlerFamily(col) : undefined
    if (op === '_null') {
      const isNull = rule.value === true || rule.value === 'true' || rule.value === '1'
      filters.push({ field: rule.field, op: isNull ? 'is null' : 'is not null' })
      return
    }
    if (op === '_between') {
      // Share c_*'s parser so a comma-STRING value ("10,20") — how runtime `?filter[x][_between]=10,20`
      // params ALWAYS arrive — serves identically to a [low,high] array (S6). Coerce both bounds so the
      // >= / <= compares match the stored type (numeric/date).
      const [low, high] = parseBetweenValues(rule.value)
      filters.push({
        field: rule.field,
        op: 'between',
        value: [this.coerce(low, family, col), this.coerce(high, family, col)],
      })
      return
    }
    if (op === '_contains' || op === '_starts') {
      // LIKE is text-only. c_* rejects _contains/_starts on numeric/date; on JSON its LIKE runs over
      // the RAW stored text, which json_extract's NORMALIZED text can't reproduce — so non-text is
      // save-rejected (validateFilterServeability), and loud here as the runtime backstop.
      if (family !== 'text') {
        throw new DocModelUnsupportedError(
          `${op} is only supported on text fields on the document model (field "${rule.field}" is ${family ?? 'unknown'})`,
        )
      }
      const pattern = op === '_contains'
        ? `%${escapeLike(String(rule.value))}%`
        : `${escapeLike(String(rule.value))}%`
      filters.push({ field: rule.field, op: 'like', value: pattern })
      return
    }
    if (op === '_in') {
      // text/numeric/date → flat IN, coerced per family EXACTLY as c_* handle*In (classes A/B are
      // native now). JSON `_in` is c_*'s json_each EXISTS membership — a construction this repo does
      // NOT build — so it is save-rejected, and loud here as the runtime backstop.
      if (family === 'json') {
        throw new DocModelUnsupportedError(
          `_in on a JSON/array field ("${rule.field}") is not serviceable by the document model`,
        )
      }
      const values = parseInValues(rule.value).map((v) => this.coerce(v, family, col))
      if (values.length === 0) {
        throw new DocModelUnsupportedError(`_in requires at least one value for "${rule.field}"`)
      }
      filters.push({ field: rule.field, op: 'in', value: values })
      return
    }
    const mapped = SCALAR_OP[op]
    if (!mapped) {
      // Unreachable — every FilterOperator is handled above; kept as a loud backstop.
      throw new DocModelUnsupportedError(
        `Operator ${op} is not supported on the document model`,
      )
    }
    filters.push({ field: rule.field, op: mapped, value: this.coerce(rule.value, family, col) })
  }

  /**
   * Coerce a scalar filter value to the JSON-stored type, EXACTLY as the c_* handlers do, so
   * `json_extract(data,'$.f') <op> ?` compares LIKE types. numeric/boolean → `coerceNumericValue`
   * (boolean `'true'`→1), date → `coerceDateValue` (ISO→epoch SECONDS — the unit
   * documents.created_at/updated_at store on this substrate); text/json stay strings. Without this
   * the doc path binds the raw filter string against a TYPED JSON value — a boolean stored as int `1`
   * never matches the string `'true'` → 0 rows (issue #1167). Structural columns carry SQLite affinity
   * so they tolerate un-coerced strings, but json_extract does not — coerce unconditionally by family.
   */
  private coerce(value: unknown, family: HandlerFamily | undefined, col: EnrichedColumn | undefined): unknown {
    if (family === 'numeric' && col) return coerceNumericValue(String(value), col)
    if (family === 'date') return coerceDateValue(String(value))
    return value
  }

  /** Visible column whitelist: the stored config's fields, else every resolved column.
   *  On anonymous surfaces, internal auth user-id columns are always dropped — a view over a
   *  public collection with no explicit column config would otherwise default-expose
   *  `created_by`/`updated_by` (Better Auth user ids) to the anonymous caller. The platform's
   *  own public document API never returns these. */
  private visibleColumns(req: ViewQueryRequest): string[] {
    const base = req.columnConfig.fields.length > 0 ? req.columnConfig.fields : req.columns.map((c) => c.name)
    if (!req.anonymousPublic) return base
    return base.filter((c) => c !== 'created_by' && c !== 'updated_by')
  }

  /**
   * A `documents` row → the view row, projected to the visible columns. STRUCTURAL columns
   * (id/slug/title/status/timestamps/…) read from the document ROW; user-authored fields read
   * from `data` (the port design: on this substrate `data` holds ONLY user fields — the
   * origin implementation read everything from `data` because its projection spread the whole
   * content row into it).
   */
  private projectRow(doc: Record<string, unknown>, visible: string[]): Record<string, unknown> {
    let content: Record<string, unknown> = {}
    const raw = doc.data
    if (typeof raw === 'string') {
      try {
        const parsed: unknown = JSON.parse(raw)
        if (parsed !== null && typeof parsed === 'object') {
          content = parsed as Record<string, unknown>
        }
      } catch {
        content = {}
      }
    }
    const out: Record<string, unknown> = {}
    for (const col of visible) {
      out[col] = STRUCTURAL_COLUMNS.has(col) ? (doc[col] ?? null) : (content[col] ?? null)
    }
    return out
  }
}
