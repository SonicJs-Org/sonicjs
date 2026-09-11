# SonicJS → Postgres — Implementation Plan (Tier 2)

> Ordered, phased runbook to add **Postgres as a supported database backend**
> alongside Cloudflare D1 / SQLite, without dropping the edge flagship.
>
> **Companions:** [`portability-analysis.md`](portability-analysis.md) (feasibility + effort),
> [`postgres-portability-poc/`](postgres-portability-poc/README.md) (Kysely spike proving both chokepoints port).
>
> **Status:** proposed. No code written. This is the go/no-go design.
> **Est:** ~7–10 engineer-weeks to GA + dual-dialect test matrix.

---

## 1. Goal / non-goals

**Goal:** `DB_DRIVER=postgres` (+ `DATABASE_URL`) boots a fully-working SonicJS —
documents, versioning, ACL, media, plugins, auth — on Postgres. D1/SQLite stays
the default and the recommended edge path. One codebase, dialect chosen at runtime.

**Non-goals:** dropping D1/SQLite; multi-DB in one process; sharding; a query-builder
rewrite of all 743 `.prepare()` sites (Kysely adoption is an *optional* quality track — §9).

## 2. Strategy — keep `D1Database` as the universal seam

Every service is typed `private db: D1Database` and a **D1-compatible driver over
better-sqlite3 already exists** (`src/adapters/db/sqlite-driver.ts`). The port is
therefore *not* a rewrite — it is **one more driver + the residual dialect SQL**:

```
services (unchanged, typed against D1Database)
     │
     ├── D1 (Workers)              ← today
     ├── sqlite-driver (better-sqlite3)  ← today (self-host)
     └── postgres-driver (NEW)     ← this plan
```

Three decisions keep the residual small — each removes a whole class of edits:

| Decision | Effect |
|---|---|
| **PG keeps `0/1` integer columns for booleans** (`is_published integer`, not `boolean`) | the hundreds of `= 1` / `visible ? 1 : 0` comparisons need **zero change** |
| **`q_*` stay real columns on PG** (`GENERATED … STORED`, not dropped for expression indexes) | `DocumentRepository.list()` — the read chokepoint — needs **zero change** |
| **`postgres-driver` rewrites `?`→`$N` internally** | the 743 `.prepare('… ?')` sites run unchanged; only genuinely-divergent SQL is touched |

Residual dialect surface after those three: **~20 `json_extract` files + 1 DDL
generator + `INSERT OR IGNORE` (21 sites) + migrations + auth adapter.** Bounded.

## 3. Phase 0 — Decisions & scaffolding  *(~0.5 wk)*

- [ ] **PG client:** `postgres` (postgres.js) — no native build, Node/Bun/Deno, fast pipelining. (`pg` acceptable fallback.)
- [ ] **Driver selection:** `DB_DRIVER = d1 | sqlite | postgres` read in `adapters/node-server.ts` + `my-sonicjs-app/src/self-host.ts`. Default `d1`.
- [ ] **`data`/`metadata` column type on PG:** `jsonb` (needed so `->>` works). Driver returns them already-parsed; guard `rowToDocument`/projection `JSON.parse` to accept object-or-string (2 files: `document-repository.ts`, `document-projection.ts`).
- [ ] **Gen-col strategy:** `GENERATED ALWAYS AS ((data->>'path')::cast) STORED` — preserves the `q_*` column contract. (`->>` is immutable → legal in STORED.)
- [ ] **Dialect context:** a process-level `getDialect(): 'sqlite' | 'postgres'` (from `DB_DRIVER`) importable by the helpers in Phase 3. No threading through call sites.

## 4. Phase 1 — Postgres driver (D1Database-compatible)  *(~1.5–2 wk)*

New: `packages/core/src/adapters/db/postgres-driver.ts`, mirroring `sqlite-driver.ts`'s public shape.

- [ ] Implement `prepare(sql)` → statement with `.bind(...args)`, `.first<T>()`, `.all<T>()`, `.run()`, `.raw()`.
- [ ] **Placeholder rewrite `?`→`$1..$n`** — sequential over *unquoted* `?` only (skip `?` inside `'…'` string literals / jsonb text). Ship a fuzz test. **(Highest-risk item — §8.)**
- [ ] **`.batch([...])` → one transaction** (`BEGIN; … COMMIT;`), returns the array-of-results shape, atomic rollback on any failure (matches D1 batch atomicity — R1/R7 depend on it).
- [ ] **`.run()` meta** — `{ changes, last_row_id, duration }` from `rowCount` / `RETURNING`. Audit `last_row_id` consumers (documents use nanoid PKs → likely none).
- [ ] Result mapping: rows → plain objects; `jsonb` → JS object; `null` handling; `bigint` epoch → `number`.
- [ ] Wire into `node-server.ts` middleware + `self-host.ts` by `DB_DRIVER`.
- [ ] Unit tests: placeholder rewrite (incl. literal-embedded `?`), batch rollback, `.first`/`.all`/`.run` meta, jsonb round-trip.

**Exit:** a standard-SQL query (`getById`, `list` with no divergent SQL) returns correct rows on PG.

## 5. Phase 2 — Postgres schema & migrations  *(~1–1.5 wk)*

- [ ] `packages/core/migrations/pg/0001_core.sql`, `pg/0002_documents.sql` — PG dialect:
  - keep `integer` 0/1 for boolean flags; text (nanoid) PKs (no `AUTOINCREMENT`).
  - `data`/`metadata` → `jsonb`.
  - `unixepoch()` default → `extract(epoch from now())::bigint`.
  - **partial UNIQUE indexes port near-verbatim** — PG supports `… WHERE` (idx_documents_one_current_draft, one_published, unique_slug, one_translation_per_locale). R6 concurrency guarantee holds.
  - drop the static VIRTUAL-col note (runtime-generated in Phase 3).
- [ ] Extend `packages/core/scripts/generate-migrations.ts` to emit a **PG bundle** (`migrations-bundle.pg.ts`) beside the SQLite one; runner selects by dialect.
- [ ] `MigrationService` dialect-aware: pick bundle + `information_schema` vs `pragma` self-heal path.
- [ ] Re-sync `my-sonicjs-app/migrations/pg/` + regen bundle (R9 discipline, per-dialect).

## 6. Phase 3 — Residual dialect SQL in services  *(~1.5–2 wk — the core work)*

- [ ] **New `packages/core/src/utils/sql-dialect.ts`:** `jsonExtract(col, '$.path', {as?})` → `json_extract(col,'$.path')` (sqlite) / `col->>'path'` (pg); `upsertIgnore(table, cols, conflictCols)` → `INSERT OR IGNORE` / `INSERT … ON CONFLICT DO NOTHING`; `nowEpoch()`.
- [ ] **`document-scalar-schema.ts`** — branch the generator:
  - DDL: sqlite `… AS (json_extract(data,'$.p')) VIRTUAL` → pg `… GENERATED ALWAYS AS ((data->>'p')::<cast>) STORED`; `affinity()` → PG type map (`text`/`double precision`/`bigint`).
  - Introspection: `pragma_table_xinfo('documents')` / `sqlite_master` → `information_schema.columns` / `pg_indexes`.
  - **Column NAME + index DDL unchanged** → `list()` untouched.
- [ ] **Replace the 38 `json_extract` sites (20 files)** with `jsonExtract()`. Targets:
  `plugins/redirect-management/middleware/redirect.ts` (6), `services/plugin-service.ts` (3),
  `routes/api.ts` (3), `utils/query-filter.ts` (2), `routes/admin-dashboard.ts` (2),
  `routes/admin-content.ts` (2), `plugins/wire.ts` (2), `plugins/redirect-management/services/redirect.ts` (2),
  `plugins/core-plugins/menu-plugin/services/menu-reconcile.ts` (2),
  `plugins/core-plugins/email-reconciliation/index.ts` (2), `middleware/plugin-middleware.ts` (2),
  + 9 single-hit files (`plugin-bootstrap`, `media-documents`, `api-media`, `webhooks`,
  `security-audit-service`, `menu-repository`, `middleware/menu`, `document-scalar-schema`, `services/plugin-service`).
- [ ] **Replace `INSERT OR IGNORE`/`OR REPLACE` (21 sites)** with `upsertIgnore()`.
- [ ] No-change confirmations: `COALESCE(MAX)+1` (3 sites, standard SQL — R6), keyset pagination, ACL SQL.

**Exit:** documents create/saveDraft/publish/unpublish/erase + media + plugins produce valid PG SQL. Spike (`postgres-portability-poc/`) already proved list + saveDraft compile.

## 7. Phase 4 — Better Auth on Postgres  *(~0.5–1 wk)*

- [ ] `src/auth/config.ts` — dialect branch: keep `withCloudflare(drizzle(D1))` on Workers; use Better Auth's native `pg`/Kysely adapter on PG, reusing the `auth_*` tables from `pg/0001_core.sql`.
- [ ] Verify session + RBAC (`c.get('user')` shape) end-to-end on PG (the analysis flags this as the one untested seam).

## 8. Phase 5 — Dual-dialect test matrix  *(~1.5–2 wk, overlaps 4–6)*

- [ ] **`src/__tests__/utils/d1-postgres.ts`** — pg→D1 shim mirroring `d1-sqlite.ts`, backed by **`pglite`** (embedded PG, in-process — CI-friendly, no docker) or a testcontainer.
- [ ] Parametrize `documents.sqlite.test.ts` + `**/*.integration.test.ts` over `DIALECT=sqlite|postgres` (R10 — real-DB coverage; mocks prove nothing).
- [ ] New cases: driver placeholder-rewrite fuzz, batch rollback atomicity, STORED gen-col filter parity, `->>`/facet filter parity, `ON CONFLICT` upsert, partial-unique concurrent-version rejection (R6).
- [ ] E2E: CI lane running existing Playwright specs against a PG-backed `self-host` (tag `@database`). New spec `tests/e2e/68-postgres-smoke.spec.ts` (R11) — write, don't run locally.

## 9. Optional track — Kysely (quality, not on critical path)

The merged spike proves Kysely compiles both chokepoints to both dialects and
**deletes the R5 bind-counting bug class**. Adopt *incrementally* after GA, starting
with `document-repository.ts` then `documents.ts`, to retire raw SQL for compile-time
type safety + a single `sql\`\`` seam for the 20 json files. **Not required for PG GA** —
the driver-shim + helpers path ships first and faster.

## 10. Risk register

| Risk | Sev | Mitigation |
|---|---|---|
| `?`→`$N` rewrite corrupts `?` inside string/jsonb literals | **High** | rewrite unquoted `?` only; fuzz test; consider requiring `$n` in new SQL |
| D1 `.batch()` atomicity vs PG txn divergence (R1/R7) | Med | wrap batch in one txn; atomicity test with mid-batch failure |
| STORED gen-col rejects non-immutable expr | Low | `->>` + `::cast` are immutable — verified legal |
| `jsonb` double-parse in `rowToDocument` | Low | typeof guard (2 files) |
| Auth adapter untested on PG | Med | Phase 4 e2e gate before GA |
| Migration drift SQLite vs PG bundles | Med | per-dialect R9 regen + a schema-parity test |

## 11. Effort roll-up

| Phase | Weeks |
|---|---|
| 0 decisions/scaffold | 0.5 |
| 1 PG driver | 1.5–2 |
| 2 schema/migrations | 1–1.5 |
| 3 residual dialect SQL | 1.5–2 |
| 4 auth | 0.5–1 |
| 5 test matrix | 1.5–2 (overlap) |
| 6 docs/rollout | 0.5 |
| **Total** | **~7–10 wk** (1 eng) |

## 12. Rollout

- Ships behind `DB_DRIVER` — default `d1`, PG strictly opt-in. Zero impact on existing installs.
- Docs: `DATABASE_URL`, `docker-compose` PG service, self-host guide, "which tier" matrix update.
- GA gate: full dual-dialect unit + integration + PG e2e green.
```
