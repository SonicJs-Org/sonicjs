// Compile-only Kysely prototype of DocumentRepository.list().
// Proves ONE TypeScript builder compiles to correct SQLite AND Postgres SQL.
// No DB connection — uses DummyDriver + each dialect's QueryCompiler.
import {
  Kysely, DummyDriver,
  SqliteAdapter, SqliteQueryCompiler, SqliteIntrospector,
  PostgresAdapter, PostgresQueryCompiler, PostgresIntrospector,
  sql,
} from 'kysely'

// --- compile-only Kysely instances (never touch a real DB) ---
const mk = (Adapter, Compiler, Introspector) =>
  new Kysely({
    dialect: {
      createAdapter: () => new Adapter(),
      createDriver: () => new DummyDriver(),
      createIntrospector: (db) => new Introspector(db),
      createQueryCompiler: () => new Compiler(),
    },
  })

const sqlite = mk(SqliteAdapter, SqliteQueryCompiler, SqliteIntrospector)
const pg = mk(PostgresAdapter, PostgresQueryCompiler, PostgresIntrospector)

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/

// Faithful port of DocumentRepository.list() — same branch structure, expressed in Kysely.
// `bool` lets the PG build emit real booleans (`= true`) while SQLite stays `= 1`.
function buildList(db, tenantId, opts = {}, { bool } = { bool: (n) => n }) {
  const limit = Math.min(opts.limit ?? 50, 200)
  const status = opts.status ?? 'published'
  const useFacetJoin = !!opts.facetFilter

  // Always alias documents as `d` — Kysely handles alias resolution, so the manual
  // `p` string-prefix from the raw version disappears entirely.
  let q = db.selectFrom('documents as d').selectAll('d')
  if (useFacetJoin) q = q.innerJoin('document_facets as f', 'f.document_id', 'd.id')

  q = q.where('d.tenant_id', '=', tenantId)
       .where('d.deleted_at', 'is', null)

  if (opts.typeId) q = q.where('d.type_id', '=', opts.typeId)

  if (status === 'published') q = q.where('d.is_published', '=', bool(1))
  else if (status === 'draft') q = q.where('d.is_current_draft', '=', bool(1))
  else q = q.where((eb) => eb.or([
    eb('d.is_published', '=', bool(1)),
    eb('d.is_current_draft', '=', bool(1)),
  ]))

  if (opts.facetFilter) q = q
    .where('f.field_name', '=', opts.facetFilter.field)
    .where('f.value_text', '=', opts.facetFilter.value)

  if (opts.timeWindow) {
    const now = opts.now ?? 0
    q = q.where((eb) => eb.and([
      eb.or([eb('d.scheduled_at', 'is', null), eb('d.scheduled_at', '<=', now)]),
      eb.or([eb('d.expires_at', 'is', null), eb('d.expires_at', '>', now)]),
    ]))
  }

  if (opts.locale && opts.locale !== 'default') q = q.where('d.locale', '=', opts.locale)
  if (opts.parentRootId !== undefined) q = q.where('d.parent_root_id', '=', opts.parentRootId)

  // Dynamic generated-column filters. sql.ref() quotes the identifier per-dialect and
  // rejects nothing on its own, so keep the format guard as defense-in-depth.
  for (const sf of opts.scalarFilters ?? []) {
    if (!SAFE_IDENTIFIER.test(sf.column)) throw new Error(`Unsafe filter column: ${sf.column}`)
    q = q.where(sql.ref(`d.${sf.column}`), '=', sf.value)
  }

  // Keyset cursor.
  if (opts.cursorUpdatedAt !== undefined && opts.cursorId) {
    const c = opts.cursorUpdatedAt, id = opts.cursorId
    q = q.where((eb) => eb.or([
      eb('d.updated_at', '<', c),
      eb.and([eb('d.updated_at', '=', c), eb('d.id', '<', id)]),
    ]))
  }

  const dir = opts.sortDir === 'ASC' ? 'asc' : 'desc'
  if (opts.sortColumn) {
    if (!SAFE_IDENTIFIER.test(opts.sortColumn)) throw new Error(`Unsafe sort column: ${opts.sortColumn}`)
    q = q.orderBy(sql.ref(`d.${opts.sortColumn}`), dir).orderBy('d.id', dir)
  } else {
    q = q.orderBy('d.updated_at', dir).orderBy('d.id', dir)
  }

  return q.limit(limit)
}

// Exercise EVERY branch at once.
const opts = {
  typeId: 'blog_post',
  status: 'all',
  locale: 'en',
  parentRootId: 'root-123',
  facetFilter: { field: 'tags', value: 'homepage' },
  timeWindow: true,
  now: 1_700_000_000,
  scalarFilters: [{ column: 'q_tst_rating', value: 4 }],
  cursorUpdatedAt: 1_699_000_000,
  cursorId: 'doc-abc',
  sortColumn: 'q_tst_rating',
  sortDir: 'DESC',
  limit: 50,
}

const show = (label, db, o) => {
  const { sql: text, parameters } = buildList(db, 'default', o).compile()
  console.log(`\n===== ${label} =====`)
  console.log(text)
  console.log('params:', JSON.stringify(parameters))
}

console.log('########## FULL-BRANCH QUERY (numeric booleans, both dialects) ##########')
show('SQLite (D1)  — numeric bools', sqlite, opts)
show('Postgres     — numeric bools', pg, opts)

console.log('\n\n########## POSTGRES with REAL booleans (bool: n => n===1) ##########')
{
  const { sql: text, parameters } = buildList(pg, 'default', opts, { bool: (n) => n === 1 }).compile()
  console.log(text)
  console.log('params:', JSON.stringify(parameters))
}

console.log('\n\n########## SIMPLE published list (typical hot path) ##########')
show('SQLite (D1)', sqlite, { typeId: 'blog_post', status: 'published', timeWindow: true, now: 1_700_000_000 })
show('Postgres', pg, { typeId: 'blog_post', status: 'published', timeWindow: true, now: 1_700_000_000 })
