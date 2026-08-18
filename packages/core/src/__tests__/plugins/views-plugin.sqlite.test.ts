/**
 * Real-SQLite coverage for the Views plugin engine (ported doc-model Views).
 *
 * Documents are seeded through the REAL write path (`DocumentsService` — create /
 * publish / saveDraft / softDelete), so the axis flags and version rows are exactly
 * what production writes; the Views engine reads them back through the full pipeline
 * (`ViewService` → `DocumentQueryProvider` → `ViewsDocumentRepository`).
 *
 * The port-correctness regressions:
 *   C2 — version history: a root with historical/published/draft version rows appears
 *        EXACTLY ONCE in an all-status view (current-row scopes; no version sweep).
 *   C3 — native status column: a draft-status filter returns the draft rows (status
 *        lives on the row here, NOT in data.status).
 *   C4 — no fallback: an inexpressible op fails loud (DocModelUnsupportedError), and
 *        status='deleted' IS expressible (soft-deleted rows keep their document row).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import type { D1Database } from '@cloudflare/workers-types'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'
import { DocumentsService } from '../../services/documents'
import type { QueryableField } from '../../services/documents'
import { createViewService } from '../../plugins/core-plugins/views-plugin/routes/api-views'
import { VIEWS_MIGRATION_STATEMENTS } from '../../plugins/core-plugins/views-plugin/migrations'
import { DocumentQueryProvider, DocModelUnsupportedError } from '../../plugins/core-plugins/views-plugin/services/document-query-provider'
import { ViewsDocumentRepository, d1Executor } from '../../plugins/core-plugins/views-plugin/services/views-document-repository'
import { DocumentCollectionResolver } from '../../plugins/core-plugins/views-plugin/services/view-collection-resolver'
import { validateFilterServeability } from '../../plugins/core-plugins/views-plugin/routes/admin-views'
import { coerceDateValue } from '../../plugins/core-plugins/views-plugin/services/filter-handlers'
import { encodeCursor, decodeCursor } from '../../plugins/core-plugins/views-plugin/services/cursor'
import { ViewCacheService } from '../../plugins/core-plugins/views-plugin/services/view-cache'
import { getCollectionRegistry, resetCollectionRegistry } from '../../services/collection-registry'
import { DocumentPermissionsService } from '../../services/document-permissions'
import type { KVNamespace } from '@cloudflare/workers-types'
import type { HandlerFamily } from '../../plugins/core-plugins/views-plugin/services/types'
import type { JsonEnvelope } from '../../plugins/core-plugins/views-plugin/services/response-formatter'

const TYPE_ID = 'review'
const FIELDS: QueryableField[] = [
  { name: 'rating', path: '$.rating', kind: 'scalar', type: 'integer', column: 'q_rev_rating' },
  { name: 'summary', path: '$.summary', kind: 'scalar', type: 'text' }, // un-promoted → json_extract
]

let db: TestD1
const asD1 = (): D1Database => db as unknown as D1Database

function docs(): DocumentsService {
  return new DocumentsService(asD1(), {
    queryableFields: FIELDS,
    tenantId: 'default',
    typeSchemaVersion: 1,
    versioning: true,
  })
}

function createInput(title: string, data: Record<string, unknown>, publishOnCreate = false) {
  return {
    typeId: TYPE_ID,
    tenantId: 'default',
    locale: 'default',
    parentRootId: '',
    slug: title.toLowerCase(),
    title,
    zone: null,
    sortOrder: 0,
    visible: true,
    data,
    metadata: {},
    publishOnCreate,
  }
}

async function seedView(
  id: string,
  name: string,
  cfg: { filter?: unknown; sort?: unknown; columns?: unknown; pageSize?: number; isPublic?: boolean; collectionId?: string },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO views
         (id, name, collection_id, filter_config, sort_config, columns_config, page_size, is_public, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 1, 1)`,
    )
    .bind(
      id,
      name,
      cfg.collectionId ?? TYPE_ID,
      cfg.filter ? JSON.stringify(cfg.filter) : null,
      cfg.sort ? JSON.stringify(cfg.sort) : null,
      cfg.columns ? JSON.stringify(cfg.columns) : null,
      cfg.pageSize ?? 25,
      cfg.isPublic ? 1 : 0,
    )
    .run()
}

/** Execute a view and return the offset JSON envelope (throws on any other shape). */
async function run(name: string, query: Record<string, string> = {}, opts?: { forcePublished?: boolean }): Promise<JsonEnvelope> {
  const result = await createViewService(asD1()).execute(name, query, opts)
  if (!('json' in result)) throw new Error('expected JSON result')
  const { json } = result
  if (!('page' in json.meta)) throw new Error('expected offset meta')
  return json as JsonEnvelope
}

beforeEach(async () => {
  db = createTestD1()
  await db
    .prepare(
      `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
       VALUES (?,?,?,'{}',?,'{}','system',1,0,1,1,1)`,
    )
    .bind(TYPE_ID, TYPE_ID, 'Review', JSON.stringify(FIELDS))
    .run()
  await db.applyScalarSchema(TYPE_ID, FIELDS)

  // The plugin's onBoot storage provisioning — run TWICE to prove idempotence.
  for (const stmt of VIEWS_MIGRATION_STATEMENTS) await db.prepare(stmt).run()
  for (const stmt of VIEWS_MIGRATION_STATEMENTS) await db.prepare(stmt).run()

  const s = docs()
  // A — published on create.
  await s.create(createInput('Alpha', { rating: 5, summary: 'excellent product' }, true), 'u1')
  // B — published, then an edit forks a current draft ALONGSIDE the published row
  //     (two live rows, one root: the C2 double-count trap).
  const b = await s.create(createInput('Beta', { rating: 4, summary: 'beta thing' }, true), 'u1')
  await s.saveDraft(b.rootId, { title: 'Beta', data: { rating: 2, summary: 'beta draft edit' } }, 'u1')
  // C — draft only.
  await s.create(createInput('Gamma', { rating: 3, summary: 'gamma draft' }), 'u1')
  // D — draft, then soft-deleted.
  const d = await s.create(createInput('Delta', { rating: 1, summary: 'gone' }), 'u1')
  await s.softDelete(d.id)
  // E — three version rows on one root: v1 (published→superseded, flags cleared),
  //     v2 (published), v3 (current draft). The version-sweep killer case.
  const e = await s.create(createInput('Epsilon', { rating: 5, summary: 'v one' }, true), 'u1')
  const e2 = await s.saveDraft(e.rootId, { title: 'Epsilon', data: { rating: 5, summary: 'v two' } }, 'u1')
  await s.publish(e2.id, 'u1')
  await s.saveDraft(e.rootId, { title: 'Epsilon', data: { rating: 5, summary: 'v three' } }, 'u1')
})
afterEach(() => db.close())

describe('C2 — current-row scopes (no version sweep, no draft+published double count)', () => {
  it('an all-status view returns each root EXACTLY once', async () => {
    await seedView('v-all', 'all-reviews', { columns: { fields: ['id', 'title', 'status', 'rating'] }, sort: [{ field: 'title', direction: 'asc' }] })
    const { data, meta } = await run('all-reviews')
    // Current rows, non-deleted: Alpha, Beta(draft v2), Gamma, Epsilon(draft v3). Delta is deleted.
    expect(meta.total).toBe(4)
    expect(data.map((r) => r['title'])).toEqual(['Alpha', 'Beta', 'Epsilon', 'Gamma'])
    // Beta appears with its DRAFT values (the current row), not the published v1's.
    const beta = data.find((r) => r['title'] === 'Beta')!
    expect(beta['rating']).toBe(2)
  })

  it('a published view returns each root exactly once (Epsilon: v2, not v1)', async () => {
    await seedView('v-pub', 'pub-reviews', {
      filter: { rules: [{ field: 'status', operator: '_eq', value: 'published' }] },
      columns: { fields: ['title', 'summary'] },
      sort: [{ field: 'title', direction: 'asc' }],
    })
    const { data, meta } = await run('pub-reviews')
    expect(meta.total).toBe(3) // Alpha, Beta (published v1), Epsilon (published v2)
    expect(data.map((r) => r['title'])).toEqual(['Alpha', 'Beta', 'Epsilon'])
    const epsilon = data.find((r) => r['title'] === 'Epsilon')!
    expect(epsilon['summary']).toBe('v two') // the LIVE published version, not historical v1
  })
})

describe('C3 — native status column (not data.status)', () => {
  it('a draft-status filter returns the draft rows (non-empty)', async () => {
    await seedView('v-drafts', 'draft-reviews', {
      filter: { rules: [{ field: 'status', operator: '_eq', value: 'draft' }] },
      columns: { fields: ['title', 'status'] },
      sort: [{ field: 'title', direction: 'asc' }],
    })
    const { data, meta } = await run('draft-reviews')
    expect(meta.total).toBe(3) // Beta draft v2, Gamma, Epsilon draft v3
    expect(data.map((r) => r['title'])).toEqual(['Beta', 'Epsilon', 'Gamma'])
    expect(data.every((r) => r['status'] === 'draft')).toBe(true)
  })

  it('structural columns project from the ROW; user fields from data', async () => {
    await seedView('v-proj', 'proj-reviews', {
      filter: { rules: [{ field: 'status', operator: '_eq', value: 'published' }] },
      columns: { fields: ['id', 'title', 'status', 'rating', 'summary'] },
      sort: [{ field: 'title', direction: 'asc' }],
    })
    const { data } = await run('proj-reviews')
    const alpha = data[0]!
    expect(alpha['title']).toBe('Alpha')       // structural (row)
    expect(alpha['status']).toBe('published')  // structural (row) — absent from data entirely
    expect(typeof alpha['id']).toBe('string')  // structural (row)
    expect(alpha['rating']).toBe(5)            // user field (data)
    expect(alpha['summary']).toBe('excellent product')
  })
})

describe('C4 — deleted is expressible; inexpressible ops fail loud', () => {
  it("status _eq 'deleted' returns the soft-deleted row", async () => {
    await seedView('v-del', 'deleted-reviews', {
      filter: { rules: [{ field: 'status', operator: '_eq', value: 'deleted' }] },
      columns: { fields: ['title'] },
    })
    const { data, meta } = await run('deleted-reviews')
    expect(meta.total).toBe(1)
    expect(data[0]!['title']).toBe('Delta')
  })

  it('_contains on a non-text field throws DocModelUnsupportedError (no silent divergence)', async () => {
    const provider = new DocumentQueryProvider(new ViewsDocumentRepository(d1Executor(asD1())))
    const resolver = new DocumentCollectionResolver(asD1())
    const { enrichedColumns } = await resolver.resolve(TYPE_ID)
    await expect(
      provider.query({
        tableName: 'documents',
        collectionId: TYPE_ID,
        columns: enrichedColumns,
        filters: [{ field: 'rating', operator: '_contains', value: '5' }],
        sort: [],
        columnConfig: { fields: ['title'] },
        pagination: { defaultLimit: 25, maxLimit: 100 },
        page: 1,
        limit: 25,
      }),
    ).rejects.toBeInstanceOf(DocModelUnsupportedError)
  })
})

describe('engine — filters, groups, public invariant, promoted columns', () => {
  it('promoted q_* filter + un-promoted json_extract LIKE filter both resolve', async () => {
    await seedView('v-filter', 'filtered-reviews', {
      filter: {
        rules: [
          { field: 'rating', operator: '_gte', value: 4 },        // promoted q_rev_rating
          { field: 'summary', operator: '_contains', value: 'v ' }, // json_extract LIKE
        ],
      },
      columns: { fields: ['title', 'summary'] },
    })
    const { data, meta } = await run('filtered-reviews')
    expect(meta.total).toBe(1) // only Epsilon's current draft: rating 5, summary 'v three'
    expect(data[0]!['summary']).toBe('v three')
  })

  it('OR-group admits either disjunct, AND-ed with the top-level filters', async () => {
    await seedView('v-group', 'grouped-reviews', {
      filter: {
        rules: [],
        groups: [{ match: 'or', rules: [
          { field: 'title', operator: '_eq', value: 'Gamma' },
          { field: 'rating', operator: '_gte', value: 5 },
        ] }],
      },
      columns: { fields: ['title'] },
      sort: [{ field: 'title', direction: 'asc' }],
    })
    const { data, meta } = await run('grouped-reviews')
    // all-scope current rows matching (title=Gamma OR rating>=5): Alpha(5), Gamma, Epsilon(5)
    expect(meta.total).toBe(3)
    expect(data.map((r) => r['title'])).toEqual(['Alpha', 'Epsilon', 'Gamma'])
  })

  it('forcePublished excludes drafts + deleted non-overridably (the public invariant)', async () => {
    await seedView('v-public', 'public-reviews', { columns: { fields: ['title', 'status'] }, sort: [{ field: 'title', direction: 'asc' }] })
    // Even a hostile runtime override cannot re-admit drafts.
    const { data, meta } = await run('public-reviews', { 'filter[status][_eq]': 'draft' }, { forcePublished: true })
    expect(meta.total).toBe(3)
    expect(data.every((r) => r['status'] === 'published')).toBe(true)
  })
})

// ─────────────────────────────────────────────────────────────────────────
// Value coercion (#1167 ported) + S6 comma-string _between + native numeric _in (A/B).
//
// These need an UN-PROMOTED numeric/boolean field so the read hits `json_extract(data,'$.f')` —
// which returns a TYPED value with NO SQLite affinity, so an un-coerced string filter value
// silently mis-matches. A `catalog` type carries two such fields.
// ─────────────────────────────────────────────────────────────────────────
const CATALOG_TYPE = 'catalog'
const CATALOG_FIELDS: QueryableField[] = [
  { name: 'price', path: '$.price', kind: 'scalar', type: 'number' },       // un-promoted → json_extract, family numeric
  { name: 'featured', path: '$.featured', kind: 'scalar', type: 'boolean' }, // un-promoted → json_extract, family numeric (boolean)
]

async function seedCatalog(): Promise<void> {
  await db
    .prepare(
      `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
       VALUES (?,?,?,'{}',?,'{}','system',1,0,1,1,1)`,
    )
    .bind(CATALOG_TYPE, CATALOG_TYPE, 'Catalog', JSON.stringify(CATALOG_FIELDS))
    .run()
  await db.applyScalarSchema(CATALOG_TYPE, CATALOG_FIELDS)
  const s = new DocumentsService(asD1(), {
    queryableFields: CATALOG_FIELDS,
    tenantId: 'default',
    typeSchemaVersion: 1,
    versioning: true,
  })
  await s.create({ ...createInput('Cheap', { price: 20, featured: false }, true), typeId: CATALOG_TYPE }, 'u1')
  await s.create({ ...createInput('Mid', { price: 100, featured: true }, true), typeId: CATALOG_TYPE }, 'u1')
  await s.create({ ...createInput('Fancy', { price: 500, featured: true }, true), typeId: CATALOG_TYPE }, 'u1')
}

async function queryCatalog(filters: Array<{ field: string; operator: FilterOperatorLike; value: unknown }>) {
  const provider = new DocumentQueryProvider(new ViewsDocumentRepository(d1Executor(asD1())))
  const { enrichedColumns } = await new DocumentCollectionResolver(asD1()).resolve(CATALOG_TYPE)
  return provider.query({
    tableName: 'documents',
    collectionId: CATALOG_TYPE,
    columns: enrichedColumns,
    // The provider only reads .field/.operator/.value; the wider FilterRule shape is satisfied at the callsite.
    filters: filters as unknown as Parameters<typeof provider.query>[0]['filters'],
    sort: [],
    columnConfig: { fields: ['title', 'price', 'featured'] },
    pagination: { defaultLimit: 25, maxLimit: 100 },
    page: 1,
    limit: 25,
  })
}
type FilterOperatorLike = '_eq' | '_neq' | '_gt' | '_gte' | '_lt' | '_lte' | '_between' | '_in' | '_contains' | '_starts' | '_null'

describe('value coercion + comma-string _between + native numeric _in (#1167 / S6 / A-B)', () => {
  beforeEach(seedCatalog)

  it('boolean _eq with a STRING value ("true") matches — coercion parity (#1167)', async () => {
    // Break-it proof: without `coerce`, json_extract($.featured)=1 is compared to the STRING 'true'
    // (1 = 'true' → false) → 0 rows. Coercion maps 'true'→1, so the two featured docs match.
    const { rows, total } = await queryCatalog([{ field: 'featured', operator: '_eq', value: 'true' }])
    expect(total).toBe(2)
    expect(rows.map((r) => r['title']).sort()).toEqual(['Fancy', 'Mid'])
  })

  it('numeric _gte with a STRING value ("100") matches on the json_extract path (#1167)', async () => {
    // Break-it proof: without coercion, json_extract($.price) (a NUMBER) >= '100' (TEXT) is always
    // false (numbers sort before text in SQLite) → 0 rows.
    const { rows, total } = await queryCatalog([{ field: 'price', operator: '_gte', value: '100' }])
    expect(total).toBe(2)
    expect(rows.map((r) => r['title']).sort()).toEqual(['Fancy', 'Mid'])
  })

  it('_between accepts a comma-STRING value ("20,100") — S6 (runtime query-param shape)', async () => {
    // Break-it proof: the pre-fix repo threw "'between' requires a [low, high] array" on a string.
    // parseBetweenValues splits "20,100"; coercion makes the >=/<= compares numeric → Cheap + Mid.
    const { rows, total } = await queryCatalog([{ field: 'price', operator: '_between', value: '20,100' }])
    expect(total).toBe(2)
    expect(rows.map((r) => r['title']).sort()).toEqual(['Cheap', 'Mid'])
  })

  it('numeric _in with a comma-STRING value ("20,500") serves natively — A/B', async () => {
    // Break-it proof: the pre-fix provider threw "_in is only supported on text fields" for numeric.
    const { rows, total } = await queryCatalog([{ field: 'price', operator: '_in', value: '20,500' }])
    expect(total).toBe(2)
    expect(rows.map((r) => r['title']).sort()).toEqual(['Cheap', 'Fancy'])
  })
})

// ─────────────────────────────────────────────────────────────────────────
// MUST-FIX 1 — date-family filter values bind epoch SECONDS (this substrate's unit).
// documents.created_at/updated_at store `unixepoch` SECONDS (documentSecondsToMs() is the ms
// boundary shim). The pre-fix coerceDateValue bound ISO→epoch MILLISECONDS: a seconds column
// compared against a ms bind makes _gte match NOTHING and _lte match EVERYTHING — silent
// mis-selection, the #1167 class on the time axis. Each pipeline test below asserts a
// PARTITION (some rows in, some out), which the ms bind cannot produce in either direction —
// revert coerceDateValue to ms and every case goes green→red (break-it proof).
// ─────────────────────────────────────────────────────────────────────────
describe('MUST-FIX 1 — date filters bind epoch seconds against real rows', () => {
  const SECS = (y: number, m: number, d: number) => Math.floor(Date.UTC(y, m - 1, d) / 1000)

  beforeEach(async () => {
    // Pin each root's rows to a known creation time, in the write path's own unit (seconds).
    for (const [title, ts] of [
      ['Alpha', SECS(2026, 1, 15)],
      ['Beta', SECS(2026, 3, 15)],
      ['Gamma', SECS(2026, 5, 15)],
      ['Epsilon', SECS(2026, 7, 15)],
    ] as const) {
      await db.prepare('UPDATE documents SET created_at = ? WHERE title = ?').bind(ts, title).run()
    }
  })

  it('coerceDateValue: ISO → epoch SECONDS; raw epoch strings pass through', () => {
    expect(coerceDateValue('2026-02-01')).toBe(SECS(2026, 2, 1))
    expect(coerceDateValue('2026-02-01T00:00:00Z')).toBe(SECS(2026, 2, 1))
    expect(coerceDateValue(String(SECS(2026, 2, 1)))).toBe(SECS(2026, 2, 1))
  })

  it('_gte with an ISO date partitions the rows (a ms bind matches NOTHING)', async () => {
    await seedView('v-date-gte', 'date-gte', {
      filter: { rules: [{ field: 'created_at', operator: '_gte', value: '2026-04-01' }] },
      columns: { fields: ['title'] },
      sort: [{ field: 'created_at', direction: 'asc' }],
    })
    const { data, meta } = await run('date-gte')
    // all-scope current rows: Alpha, Beta, Gamma, Epsilon (Delta soft-deleted). ≥ Apr 1 → Gamma, Epsilon.
    expect(meta.total).toBe(2)
    expect(data.map((r) => r['title'])).toEqual(['Gamma', 'Epsilon'])
  })

  it('_lte with an ISO date partitions the rows (a ms bind matches EVERYTHING)', async () => {
    await seedView('v-date-lte', 'date-lte', {
      filter: { rules: [{ field: 'created_at', operator: '_lte', value: '2026-04-01' }] },
      columns: { fields: ['title'] },
      sort: [{ field: 'created_at', direction: 'asc' }],
    })
    const { data, meta } = await run('date-lte')
    expect(meta.total).toBe(2)
    expect(data.map((r) => r['title'])).toEqual(['Alpha', 'Beta'])
  })

  it('_between with a comma-STRING of ISO dates (runtime param shape) selects the window', async () => {
    await seedView('v-date-between', 'date-between', {
      filter: { rules: [{ field: 'created_at', operator: '_between', value: '2026-02-01,2026-06-01' }] },
      columns: { fields: ['title'] },
      sort: [{ field: 'created_at', direction: 'asc' }],
    })
    const { data, meta } = await run('date-between')
    expect(meta.total).toBe(2)
    expect(data.map((r) => r['title'])).toEqual(['Beta', 'Gamma'])
  })
})

// ─────────────────────────────────────────────────────────────────────────
// Polish item 4 — cursor field-level drift. The count-only check accepted a stale token when a
// sort-FIELD/dir change kept the same key count (created_at asc → updated_at asc) and silently
// mispositioned the page. New tokens carry a "field:dir" fingerprint; keyless (older) tokens
// stay accepted under the count check (back-compat contract).
// ─────────────────────────────────────────────────────────────────────────
describe('polish 4 — cursor sort-key fingerprint', () => {
  async function firstCursorPage(name: string): Promise<string> {
    const result = await createViewService(asD1()).execute(name, { paginate: 'cursor', limit: '2' })
    if (!('json' in result)) throw new Error('expected JSON result')
    const meta = result.json.meta as { nextCursor?: string | null }
    if (!meta.nextCursor) throw new Error('expected a nextCursor on page 1')
    return meta.nextCursor
  }

  it('codec round-trips the fingerprint; keyless tokens decode with keys undefined', () => {
    const token = encodeCursor({ values: [123], id: 'x', keys: ['created_at:asc'] })
    expect(decodeCursor(token)).toEqual({ values: [123], id: 'x', keys: ['created_at:asc'] })
    const legacy = encodeCursor({ values: [123], id: 'x' })
    expect(decodeCursor(legacy)?.keys).toBeUndefined()
  })

  it('a sort-FIELD change with the SAME key count rejects the stale token (break-it: pre-fix accepted)', async () => {
    await seedView('v-cur', 'cursor-view', {
      sort: [{ field: 'created_at', direction: 'asc' }],
      columns: { fields: ['title'] },
    })
    const token = await firstCursorPage('cursor-view')
    await db
      .prepare(`UPDATE views SET sort_config = '[{"field":"updated_at","direction":"asc"}]' WHERE id = 'v-cur'`)
      .run()
    await expect(
      createViewService(asD1()).execute('cursor-view', { cursor: token }),
    ).rejects.toThrow(/does not match the current sort keys/)
  })

})

// ─────────────────────────────────────────────────────────────────────────
// Cursor keyset pagination — POSITION correctness (test-audit gap #1/#2/#3). The earlier
// cursor tests covered the DRIFT-rejection (fingerprint) but not the keyset POSITION: an
// inverted comparator or a broken multi-key predicate went undetected. These page through a
// controlled corpus and assert the exact slices, so a wrong keyset SQL fails loudly.
// Dedicated document type so only these rows are in scope (no pollution from the outer seed).
// ─────────────────────────────────────────────────────────────────────────
describe('cursor keyset pagination — position + multi-key + termination', () => {
  const CUR_TYPE = 'curcorpus'
  const CUR_FIELDS: QueryableField[] = [{ name: 'n', path: '$.n', kind: 'scalar', type: 'integer' }]

  beforeEach(async () => {
    await db
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES (?,?,?,'{}',?,'{}','system',1,0,1,1,1)`,
      )
      .bind(CUR_TYPE, CUR_TYPE, 'Cursor Corpus', JSON.stringify(CUR_FIELDS))
      .run()
    await db.applyScalarSchema(CUR_TYPE, CUR_FIELDS)
    const s = new DocumentsService(asD1(), { queryableFields: CUR_FIELDS, tenantId: 'default', typeSchemaVersion: 1, versioning: false })
    for (let n = 1; n <= 5; n++) await s.create({ ...createInput(`C${n}`, { n }, true), typeId: CUR_TYPE }, 'u1')
    // Distinct, known ascending created_at by n (the write path stamps ~now for all).
    for (let n = 1; n <= 5; n++) {
      await db.prepare('UPDATE documents SET created_at = ? WHERE type_id = ? AND title = ?').bind(1_700_000_000 + n, CUR_TYPE, `C${n}`).run()
    }
  })

  /** Page fully through a cursor view; returns each page's titles + whether the cursor terminated. */
  async function pageAll(sort: unknown, limit: number): Promise<{ pages: string[][]; terminated: boolean }> {
    await db.prepare("DELETE FROM views WHERE id = 'v-cur-pos'").run()
    await seedView('v-cur-pos', 'cur-pos', { collectionId: CUR_TYPE, sort, columns: { fields: ['title'] } })
    const pages: string[][] = []
    let cursor: string | undefined
    let terminated = false
    for (let i = 0; i < 12; i++) {
      const q: Record<string, string> = { paginate: 'cursor', limit: String(limit) }
      if (cursor) q['cursor'] = cursor
      const res = await createViewService(asD1()).execute('cur-pos', q)
      if (!('json' in res)) throw new Error('expected JSON result')
      pages.push(res.json.data.map((r) => String(r['title'])))
      const meta = res.json.meta as { nextCursor?: string | null }
      if (!meta.nextCursor) { terminated = true; break }
      cursor = meta.nextCursor
    }
    return { pages, terminated }
  }

  it('single-key asc: consecutive non-overlapping slices in order; the last page ends the cursor', async () => {
    const { pages, terminated } = await pageAll([{ field: 'created_at', direction: 'asc' }], 2)
    expect(pages).toEqual([['C1', 'C2'], ['C3', 'C4'], ['C5']]) // exact position + no overlap
    expect(terminated).toBe(true) // nextCursor null on the final page (gap #3)
  })

  it('single-key desc reverses the slices (an inverted keyset comparator fails here)', async () => {
    const { pages } = await pageAll([{ field: 'created_at', direction: 'desc' }], 2)
    expect(pages).toEqual([['C5', 'C4'], ['C3', 'C2'], ['C1']])
  })

  it('multi-key mixed-direction: the second key breaks ties within the first (gap #2)', async () => {
    // C2 & C3 share created_at; updated_at desc must order C3 before C2 inside that tie group.
    await db.prepare("UPDATE documents SET created_at = 1700000002 WHERE type_id = ? AND title IN ('C2','C3')").bind(CUR_TYPE).run()
    await db.prepare("UPDATE documents SET updated_at = 500 WHERE type_id = ? AND title = 'C2'").bind(CUR_TYPE).run()
    await db.prepare("UPDATE documents SET updated_at = 900 WHERE type_id = ? AND title = 'C3'").bind(CUR_TYPE).run()
    const { pages } = await pageAll(
      [{ field: 'created_at', direction: 'asc' }, { field: 'updated_at', direction: 'desc' }],
      2,
    )
    // created_at asc: C1 < {C2,C3} < C4 < C5; within the tie, updated_at desc → C3 then C2.
    // Paged at limit 2, the tie group spans the page-1/page-2 boundary, exercising the
    // lexicographic prefix-equality clause (created_at = ? AND updated_at < ?).
    expect(pages.flat()).toEqual(['C1', 'C3', 'C2', 'C4', 'C5'])
  })

  it('a keyless (pre-fingerprint) token still positions correctly — back-compat', async () => {
    await seedView('v-cur-bc', 'cur-bc', { collectionId: CUR_TYPE, sort: [{ field: 'created_at', direction: 'asc' }], columns: { fields: ['title'] } })
    const p1 = await createViewService(asD1()).execute('cur-bc', { paginate: 'cursor', limit: '2' })
    if (!('json' in p1)) throw new Error('expected JSON result')
    const token = (p1.json.meta as { nextCursor?: string | null }).nextCursor!
    // Strip the fingerprint to simulate a token minted before the drift-check shipped.
    const decoded = decodeCursor(token)!
    const keyless = encodeCursor({ values: decoded.values, id: decoded.id })
    const p2 = await createViewService(asD1()).execute('cur-bc', { cursor: keyless, limit: '2' })
    if (!('json' in p2)) throw new Error('expected JSON result')
    expect(p2.json.data.map((r) => String(r['title']))).toEqual(['C3', 'C4']) // correct next slice, not just self-consistent
  })
})

// ─────────────────────────────────────────────────────────────────────────
// Polish item 5 — hook invalidation when document_type id ≠ collection name. The content hooks
// carry the collection NAME; views store the type ID. Pre-fix the SELECT matched nothing for a
// DB-created type with id≠name, so its views rode the TTL instead of the hook.
// ─────────────────────────────────────────────────────────────────────────
describe('polish 5 — invalidateByCollection resolves name → type id', () => {
  function fakeKV(initial: string[]): { kv: KVNamespace; deleted: string[] } {
    const keys = new Set(initial)
    const deleted: string[] = []
    const kv = {
      list: async ({ prefix }: { prefix: string }) => ({
        keys: [...keys].filter((k) => k.startsWith(prefix)).map((name) => ({ name })),
      }),
      delete: async (name: string) => { keys.delete(name); deleted.push(name) },
    } as unknown as KVNamespace
    return { kv, deleted }
  }

  it('a view on a type whose id ≠ name is invalidated by the collection NAME (break-it: pre-fix 0 deletes)', async () => {
    await db
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('dt-articles-9f2','articles','Articles','{}','[]','{}','system',1,0,1,1,1)`,
      )
      .run()
    await db
      .prepare(
        `INSERT INTO views (id, name, collection_id, page_size, status, created_at, updated_at)
         VALUES ('v-art', 'articles-view', 'dt-articles-9f2', 25, 'active', 1, 1)`,
      )
      .run()
    const { kv, deleted } = fakeKV(['view:default:articles-view:page1', 'view:default:other-view:page1'])
    await new ViewCacheService(kv).invalidateByCollection(asD1(), 'articles')
    expect(deleted).toEqual(['view:default:articles-view:page1'])
  })

  it('id == name (every code-registered collection) still invalidates exactly its views', async () => {
    await seedView('v-inv', 'review-view', { columns: { fields: ['title'] } })
    const { kv, deleted } = fakeKV(['view:default:review-view:page1'])
    await new ViewCacheService(kv).invalidateByCollection(asD1(), TYPE_ID)
    expect(deleted).toEqual(['view:default:review-view:page1'])
  })
})

// ─────────────────────────────────────────────────────────────────────────
// Public-exposure gate (C). The anonymous JSON API (GET /api/views/:name) sets
// { forcePublished:true, anonymousPublic:true }. A view is served ONLY if it is
// is_public=1 AND its backing collection grants public read (settings.baseGrants.public
// includes 'read'). A private view OR a non-public collection 404s (NOT_FOUND) — so a view
// can never expose content the admin didn't opt into, and never a collection the doc model
// keeps private (the D5 "no is_published-only fast path" rule). The authed builder preview
// never sets anonymousPublic, so private views stay fully usable in the admin.
// ─────────────────────────────────────────────────────────────────────────
describe('C — public-exposure gate (is_public + collection public-read grant)', () => {
  const PUB_TYPE = 'pubcatalog'
  beforeEach(async () => {
    // A PUBLIC document type (baseGrants.public includes 'read') + one published doc.
    await db
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES (?,?,?,'{}','[]',?,'system',1,0,1,1,1)`,
      )
      .bind(PUB_TYPE, PUB_TYPE, 'Public Catalog', JSON.stringify({ baseGrants: { public: ['read'] } }))
      .run()
    const s = new DocumentsService(asD1(), { queryableFields: [], tenantId: 'default', typeSchemaVersion: 1, versioning: false })
    await s.create({ ...createInput('Widget', { price: 9 }, true), typeId: PUB_TYPE }, 'u1')
  })

  const anonExec = (name: string) =>
    createViewService(asD1()).execute(name, {}, { forcePublished: true, anonymousPublic: true })

  it('is_public=1 over a PUBLIC collection → served', async () => {
    await seedView('v-pub-ok', 'pub-ok', { collectionId: PUB_TYPE, isPublic: true, columns: { fields: ['title'] } })
    const res = await anonExec('pub-ok')
    if (!('json' in res)) throw new Error('expected JSON')
    expect(res.json.data.length).toBe(1)
  })

  it('is_public=0 (PRIVATE) over a public collection → 404 (break-it: pre-fix served it)', async () => {
    await seedView('v-priv', 'priv-view', { collectionId: PUB_TYPE, isPublic: false, columns: { fields: ['title'] } })
    await expect(anonExec('priv-view')).rejects.toMatchObject({ statusCode: 404 })
  })

  it('is_public=1 over a NON-public collection → 404 (collection-grant backstop, D5)', async () => {
    // TYPE_ID ('review') is seeded with settings '{}' — no baseGrants.public.
    await seedView('v-nonpub', 'nonpub-view', { collectionId: TYPE_ID, isPublic: true, columns: { fields: ['title'] } })
    await expect(anonExec('nonpub-view')).rejects.toMatchObject({ statusCode: 404 })
  })

  it('the AUTHED path (no anonymousPublic) serves a PRIVATE view — admin/preview unaffected', async () => {
    await seedView('v-priv2', 'priv-view-2', { collectionId: PUB_TYPE, isPublic: false, columns: { fields: ['title'] } })
    const res = await createViewService(asD1()).execute('priv-view-2', {}, { forcePublished: true })
    if (!('json' in res)) throw new Error('expected JSON')
    expect(res.json.data.length).toBe(1)
  })

  // Security review HIGH-2: a default (empty columns_config) public view must not expose the
  // internal auth user ids created_by/updated_by anonymously. Break-it: drop the redact filter
  // in visibleColumns → created_by appears in the anon row.
  it('anonymous surfaces redact created_by/updated_by; the authed path keeps them', async () => {
    await seedView('v-redact', 'redact-view', { collectionId: PUB_TYPE, isPublic: true }) // default = all columns
    const anon = await anonExec('redact-view')
    if (!('json' in anon)) throw new Error('expected JSON')
    const anonRow = anon.json.data[0]!
    expect('created_by' in anonRow).toBe(false)
    expect('updated_by' in anonRow).toBe(false)
    expect(anonRow['title']).toBe('Widget') // non-system fields still served
    const authed = await createViewService(asD1()).execute('redact-view', {}, { forcePublished: true })
    if (!('json' in authed)) throw new Error('expected JSON')
    expect(authed.json.data[0]!['created_by']).toBe('u1') // admin still sees them
  })

  // Security review MEDIUM-1 / code review S1: a stored page_size above the serveable ceiling
  // is capped at 100 in the response meta (repo hard-caps rows at 200; an uncapped page_size
  // truncated silently with a wrong meta). Break-it: revert the Math.min in paginationConfig → 300.
  it('page_size above the ceiling is capped at 100 in the response meta', async () => {
    await seedView('v-cap', 'cap-view', { collectionId: PUB_TYPE, isPublic: true, pageSize: 300 })
    const res = await anonExec('cap-view')
    if (!('json' in res) || !('page' in res.json.meta)) throw new Error('expected offset JSON')
    expect(res.json.meta.limit).toBe(100)
  })

  // Security review HIGH-1: anonymous reads honor per-document deny overrides ("deny wins"),
  // not just the type-level public grant. Break-it: remove filterDeniedRoots in the provider
  // → the denied doc reappears in the anon result.
  it('honors per-document deny overrides on anonymous reads ("deny wins")', async () => {
    const s = new DocumentsService(asD1(), { queryableFields: [], tenantId: 'default', typeSchemaVersion: 1, versioning: false })
    await s.create({ ...createInput('Secret', { price: 99 }, true), typeId: PUB_TYPE }, 'u1')
    // Public read-deny on the 'Widget' root seeded in this block's beforeEach.
    const widget = await db
      .prepare("SELECT root_id FROM documents WHERE type_id = ? AND slug = 'widget' AND is_published = 1")
      .bind(PUB_TYPE)
      .first<{ root_id: string }>()
    await new DocumentPermissionsService(asD1()).grantPermission({
      tenantId: 'default', rootId: widget!.root_id,
      principalType: 'public', principalId: '*', permission: 'read', effect: 'deny',
    })
    await seedView('v-deny', 'deny-view', { collectionId: PUB_TYPE, isPublic: true, columns: { fields: ['title'] } })
    const res = await anonExec('deny-view')
    if (!('json' in res)) throw new Error('expected JSON')
    const titles = res.json.data.map((r) => r['title'])
    expect(titles).toContain('Secret')     // no override → served
    expect(titles).not.toContain('Widget') // per-doc deny → filtered even though the collection is public
  })

  // Code review S2: previewDraft surfaces an unserveable op as a loud DocModelUnsupportedError
  // (which the /api/preview route maps to a 400 instead of a 500). _contains on a date-family
  // column is family-invalid on the doc model.
  it('previewDraft throws DocModelUnsupportedError on an unserveable op', async () => {
    const svc = createViewService(asD1())
    await expect(
      svc.previewDraft(
        { collection_id: PUB_TYPE, filter_config: JSON.stringify({ rules: [{ field: 'created_at', operator: '_contains', value: 'x' }] }) },
        {},
      ),
    ).rejects.toBeInstanceOf(DocModelUnsupportedError)
  })
})

// ─────────────────────────────────────────────────────────────────────────
// Builder field discovery — registry fallback. A code-defined collection registers a
// document_type whose `schema` column holds {queryableFields,settings} (NO `properties`), so
// the builder's field pickers would see structural columns only. The resolver falls back to
// the in-memory CollectionRegistry (the real CollectionConfig.schema.properties) so the
// builder can offer the collection's own fields — the fix for "Sort dropdown shows id".
// ─────────────────────────────────────────────────────────────────────────
describe('builder field discovery — CollectionRegistry fallback for code-defined collections', () => {
  const DIR_TYPE = 'directory'
  beforeEach(async () => {
    getCollectionRegistry().register([
      {
        name: DIR_TYPE,
        displayName: 'Directory',
        description: 'People',
        schema: {
          type: 'object',
          properties: {
            first_name: { type: 'string', title: 'First Name' },
            last_name: { type: 'string', title: 'Last Name' },
            department: { type: 'reference', title: 'Department', collection: 'departments' },
          },
        },
      },
    ])
    // document_type row exactly as auto-registration writes it: schema WITHOUT `properties`.
    await db
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES (?,?,?,?,'[]','{}','system',1,0,1,1,1)`,
      )
      .bind(DIR_TYPE, DIR_TYPE, 'Directory', JSON.stringify({ queryableFields: [], settings: {} }))
      .run()
  })
  afterEach(() => resetCollectionRegistry())

  it("surfaces the collection's own fields, not just structural columns", async () => {
    const cols = (await new DocumentCollectionResolver(asD1()).columnsByName(DIR_TYPE))!.enrichedColumns.map((c) => c.name)
    expect(cols).toContain('first_name')
    expect(cols).toContain('last_name')
    expect(cols).toContain('department')
    expect(cols).toContain('id') // structural columns still present
  })

  it('break-it proof: with the registry empty, only structural columns appear', async () => {
    resetCollectionRegistry() // no registry knowledge of DIR_TYPE
    const cols = (await new DocumentCollectionResolver(asD1()).columnsByName(DIR_TYPE))!.enrichedColumns.map((c) => c.name)
    expect(cols).not.toContain('first_name')
    expect(cols).toContain('id')
  })
})

// ─────────────────────────────────────────────────────────────────────────
// Gap 1 — save-time serveability rejection. `validateFilterServeability` is the pure gate the
// POST/PUT routes run after structure validation. Each rejection assertion is a break-it proof:
// delete the matching check in checkRuleServeable and the case goes green→red.
// ─────────────────────────────────────────────────────────────────────────
describe('gap 1 — save-time serveability rejection', () => {
  const families = new Map<string, HandlerFamily>([
    ['title', 'text'],
    ['status', 'text'],
    ['price', 'numeric'],
    ['created_at', 'date'],
    ['tags', 'json'],
  ])

  it('rejects JSON _in (no json_each membership on the document model)', () => {
    const err = validateFilterServeability({ rules: [{ field: 'tags', operator: '_in', value: 'a,b' }] }, families)
    expect(err).toMatch(/'_in'.*'tags'.*document model/i)
  })

  it('rejects JSON _contains (normalized-JSON LIKE parity gap)', () => {
    const err = validateFilterServeability({ rules: [{ field: 'tags', operator: '_contains', value: 'x' }] }, families)
    expect(err).toMatch(/'_contains'.*'tags'/i)
  })

  it('rejects a family-invalid op (_gt on a text field) — c_* parity', () => {
    const err = validateFilterServeability({ rules: [{ field: 'title', operator: '_gt', value: 'm' }] }, families)
    expect(err).toMatch(/'_gt'.*'title'.*text/i)
  })

  it('rejects _contains on a numeric field', () => {
    const err = validateFilterServeability({ rules: [{ field: 'price', operator: '_contains', value: '5' }] }, families)
    expect(err).toMatch(/'_contains'.*'price'.*numeric/i)
  })

  it('rejects an unserveable op inside an OR group (locating the exact rule)', () => {
    const err = validateFilterServeability(
      { rules: [], groups: [{ match: 'or', rules: [{ field: 'tags', operator: '_in', value: 'a' }] }] },
      families,
    )
    expect(err).toMatch(/groups\[0\]\.rules\[0\]/)
  })

  it('ALLOWS the entire live-corpus filter shape (status _eq + numeric _gte/_lt + boolean _eq)', () => {
    expect(
      validateFilterServeability(
        { rules: [{ field: 'status', operator: '_eq', value: 'published' }, { field: 'price', operator: '_gte', value: '100' }] },
        families,
      ),
    ).toBeNull()
  })

  it('ALLOWS status _neq and status _in-in-a-group (native status column — F/G served on this substrate)', () => {
    expect(validateFilterServeability({ rules: [{ field: 'status', operator: '_neq', value: 'draft' }] }, families)).toBeNull()
    expect(
      validateFilterServeability(
        { rules: [], groups: [{ match: 'or', rules: [{ field: 'status', operator: '_in', value: 'draft,published' }] }] },
        families,
      ),
    ).toBeNull()
  })

  it('ALLOWS numeric _in and _between (A/B + S6 are native, not rejected)', () => {
    expect(validateFilterServeability({ rules: [{ field: 'price', operator: '_in', value: '1,2' }] }, families)).toBeNull()
    expect(validateFilterServeability({ rules: [{ field: 'price', operator: '_between', value: '1,2' }] }, families)).toBeNull()
  })
})
