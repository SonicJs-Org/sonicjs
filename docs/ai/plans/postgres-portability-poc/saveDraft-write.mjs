// Compile-only Kysely prototype of the HARD write path: documents.saveDraft().
// Covers the three gnarly statements the read path never touches:
//   1. demote UPDATE
//   2. INSERT with an inline COALESCE(MAX(version_number))+1 subquery  (the R5 27-bind statement)
//   3. prune DELETE with two NOT IN (… LIMIT ?) subqueries
// All three compile to correct SQLite AND Postgres. batch() -> transaction (noted, not run).
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
const maxVersions = 20
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

const dump = (label, q) => {
  const { sql: text, parameters } = q.compile()
  console.log(`\n----- ${label} -----`)
  console.log(text)
  console.log('params:', JSON.stringify(parameters))
}

for (const [name, db, b] of [
  ['SQLite (D1) — numeric bools', sqlite, (n) => n],
  ['Postgres — REAL bools',       pg,     (n) => (typeof n === 'number' && (n === 0 || n === 1) ? n === 1 : n)],
]) {
  console.log(`\n########## ${name} ##########`)
  dump('1. demote UPDATE', buildDemote(db, b))
  dump('2. versioned INSERT (COALESCE(MAX)+1 subquery)', buildInsert(db, b))
  dump('3. prune DELETE (NOT IN + LIMIT)', buildPrune(db, b))
}

console.log(`
########## batch() -> transaction (idiom, not compiled here) ##########
await db.transaction().execute(async (trx) => {
  await buildDemote(trx).execute()
  await buildInsert(trx).execute()
  // ...derived facet/ref inserts...
  await buildPrune(trx).execute()
})
// D1 .batch([...]) becomes one transaction. Kysely runs it on pg / better-sqlite3 / libsql;
// on Workers D1 the kysely-d1 dialect maps .transaction() back onto D1 batch semantics.`)
