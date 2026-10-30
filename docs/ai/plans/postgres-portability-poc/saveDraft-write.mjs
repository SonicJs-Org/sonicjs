// Compile-only Kysely prototype of the HARD write path: documents.saveDraft().
// Covers the four gnarly statements the read path never touches:
//   1. demote UPDATE
//   2. INSERT with an inline COALESCE(MAX(version_number))+1 subquery  (the R5 27-bind statement)
//   3. prune DELETE with two NOT IN (… LIMIT ?) subqueries
//   4. the DERIVED-ROW multi-row facet INSERT, chunked against D1's 100-bind cap
//      (document-projection.ts — the dynamic half of the real batch)
// All four compile to correct SQLite AND Postgres.
// NOTE: D1 .batch() does NOT become .transaction() — kysely-d1 throws on transactions.
// See the trailer at the bottom for the compile-and-batch idiom that actually works.
import {
  Kysely, DummyDriver,
  SqliteAdapter, SqliteQueryCompiler, SqliteIntrospector,
  PostgresAdapter, PostgresQueryCompiler, PostgresIntrospector,
  sql,
} from 'kysely'

const mk = (Adapter, Compiler, Introspector) =>
  new Kysely({ dialect: {
    createAdapter: () => new Adapter(),
    createDriver: () => new DummyDriver(),
    createIntrospector: (db) => new Introspector(db),
    createQueryCompiler: () => new Compiler(),
  }})

const sqlite = mk(SqliteAdapter, SqliteQueryCompiler, SqliteIntrospector)
const pg = mk(PostgresAdapter, PostgresQueryCompiler, PostgresIntrospector)

// --- fixture ---
const t = 'default', rootId = 'root-1', prevId = 'doc-prev', newId = 'doc-new', now = 1_700_000_000
const maxVersions = 50 // DEFAULT_MAX_VERSIONS in services/documents.ts
const nd = {
  typeId: 'blog_post', typeVersion: 1, parentRootId: 'p-1', slug: 'hello', title: 'Hi',
  zone: null, sortOrder: 0, visible: true, scheduledAt: null, expiresAt: null,
  tenantId: t, locale: 'en', translationGroupId: '', data: { body: 'x' }, metadata: { seo: {} },
  ownerId: 'u1', createdBy: 'u1', updatedBy: 'u1',
}

// bool mapper: SQLite keeps 0/1 ints, PG uses real booleans.
const buildDemote  = (db, b = (n) => n) =>
  db.updateTable('documents')
    .set({ is_current_draft: b(0), updated_at: now })
    .where('id', '=', prevId).where('tenant_id', '=', t)

// The hardest statement. Raw version was INSERT…SELECT ?,?,…(subquery)…,1,0,'draft',… WHERE 1=1
// with a hand-counted 27-bind budget (R5). Kysely's values({col: subquery}) form is both safer
// (named columns, no positional counting) and dialect-neutral.
const buildInsert = (db, b = (n) => n) =>
  db.insertInto('documents').values({
    id: newId, root_id: rootId, type_id: nd.typeId, type_version: nd.typeVersion, version_of_id: prevId,
    // COALESCE(MAX)+1 stays in SQL (R6) — never computed in JS. Correlated subquery, standard SQL.
    version_number: (eb) => eb.selectFrom('documents')
      .select(sql`coalesce(max(version_number), 0) + 1`.as('v'))
      .where('root_id', '=', rootId),
    is_current_draft: b(1), is_published: b(0), status: 'draft',
    parent_root_id: nd.parentRootId, slug: nd.slug, path: null, title: nd.title, zone: nd.zone,
    sort_order: nd.sortOrder, visible: b(nd.visible ? 1 : 0), published_at: null,
    scheduled_at: nd.scheduledAt, expires_at: nd.expiresAt, deleted_at: null,
    tenant_id: nd.tenantId, locale: nd.locale, translation_group_id: nd.translationGroupId,
    data: JSON.stringify(nd.data), metadata: JSON.stringify(nd.metadata),
    owner_id: nd.ownerId, created_by: nd.createdBy, updated_by: nd.updatedBy,
    created_at: now, updated_at: now,
  })

// prune DELETE: two NOT IN subqueries, one with ORDER BY + LIMIT.
const buildPrune = (db, b = (n) => n) =>
  db.deleteFrom('documents')
    .where('root_id', '=', rootId).where('tenant_id', '=', t)
    .where('is_current_draft', '=', b(0)).where('is_published', '=', b(0))
    .where('id', 'not in', (eb) => eb.selectFrom('documents').select('id')
      .where('root_id', '=', rootId).where('tenant_id', '=', t)
      .where('is_current_draft', '=', b(0)).where('is_published', '=', b(0))
      .orderBy('version_number', 'desc').limit(maxVersions))
    .where('id', 'not in', (eb) => eb.selectFrom('documents').select('version_of_id')
      .where('version_of_id', 'is not', null).where('root_id', '=', rootId).where('tenant_id', '=', t))

// Derived facet rows (document-projection.ts). This is the part of the real batch that
// Kysely does NOT de-risk: multi-row VALUES must still be hand-chunked against the
// per-statement bind cap (D1 = 100 params, hard; Postgres = 65535). Kysely's values([...])
// array form emits one placeholder tuple per row, so the ROW count is still a budget you own.
const FACET_COLS = 10 // id, tenant_id, document_id, root_id, type_id, field_name, ordinal, value_text, value_number, created_at
const MAX_PARAMS = 90 // document-projection.ts keeps a 10-param safety margin under D1's 100
const FACET_CHUNK = Math.floor(MAX_PARAMS / FACET_COLS) // 9 rows/statement
const chunk = (arr, size) =>
  Array.from({ length: Math.ceil(arr.length / size) }, (_, i) => arr.slice(i * size, i * size + size))

// 11 tag facets -> 2 statements (9 + 2) on BOTH dialects, same as the raw version.
const facetRows = Array.from({ length: 11 }, (_, i) => ({
  id: `facet-${i}`, tenant_id: t, document_id: newId, root_id: rootId, type_id: nd.typeId,
  field_name: 'tags', ordinal: i, value_text: `tag-${i}`, value_number: null, created_at: now,
}))

const buildFacetInserts = (db) =>
  chunk(facetRows, FACET_CHUNK).map((rows) => db.insertInto('document_facets').values(rows))

const dump = (label, q) => {
  const { sql: text, parameters } = q.compile()
  console.log(`\n----- ${label} -----`)
  console.log(text)
  console.log('params:', JSON.stringify(parameters))
}

for (const [name, db, b] of [
  ['SQLite (D1) — numeric bools', sqlite, (n) => n],
  // The PLANNED design (postgres-implementation-plan.md §2) keeps 0/1 integer columns on PG,
  // so the hundreds of `= 1` comparisons need zero change. No mapper at all:
  ['Postgres — 0/1 ints (PLANNED design)', pg, (n) => n],
  // Alternative, only if PG gets real `boolean` columns: one per-dialect mapper, not 300 edits.
  ['Postgres — REAL bools (alternative)',  pg, (n) => (typeof n === 'number' && (n === 0 || n === 1) ? n === 1 : n)],
]) {
  console.log(`\n########## ${name} ##########`)
  dump('1. demote UPDATE', buildDemote(db, b))
  dump('2. versioned INSERT (COALESCE(MAX)+1 subquery)', buildInsert(db, b))
  dump('3. prune DELETE (NOT IN + LIMIT)', buildPrune(db, b))
  buildFacetInserts(db).forEach((q, i) => {
    const binds = q.compile().parameters.length
    dump(`4.${i + 1} derived facet INSERT (chunk ${i + 1} — ${binds} binds, cap ${MAX_PARAMS})`, q)
    if (binds > MAX_PARAMS) throw new Error(`bind budget blown: ${binds} > ${MAX_PARAMS}`)
  })
}

console.log(String.raw`
########## batch() atomicity — what actually works (idiom, not compiled here) ##########

Postgres / better-sqlite3 / libSQL — real interactive transactions:

  await db.transaction().execute(async (trx) => {
    await buildDemote(trx).execute()
    await buildInsert(trx).execute()
    for (const q of buildFacetInserts(trx)) await q.execute()
    await buildPrune(trx).execute()
  })

Cloudflare D1 — transactions are NOT available. kysely-d1@0.4.0 dist/index.js:95-110
throws 'Transactions are not supported yet.' from beginTransaction/commit/rollback, so
db.transaction() fails at runtime on Workers. D1's only atomic primitive is .batch().
Compile the builders and hand the statements to D1 directly:

  const queries = [buildDemote(db), buildInsert(db), ...buildFacetInserts(db), buildPrune(db)]
  const stmts = queries.map((q) => {
    const { sql, parameters } = q.compile()
    return env.DB.prepare(sql).bind(...parameters)
  })
  await env.DB.batch(stmts)   // one implicit transaction, rolls back as a unit

=> Adopting Kysely on Workers requires a small compile-and-batch shim (~1 file) to preserve
   R1/R7 atomicity. Statement ORDER still matters (demote before insert — the partial unique
   index must never see two current drafts mid-batch), exactly as in the raw version.
`)
