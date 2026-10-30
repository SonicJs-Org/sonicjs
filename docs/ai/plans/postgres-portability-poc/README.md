# Postgres Portability — Kysely Spike (compile-only)

> Measures the real effort of a SonicJS → Postgres port by porting the two
> chokepoint code paths to **Kysely** and proving one TypeScript builder
> compiles to correct **SQLite (D1)** *and* **Postgres** SQL.
>
> **Status:** spike / measurement only. No production code changed.
> **Measured:** 2026-09-02, re-verified 2026-10-20 against `kysely@0.27.6` (pinned).
> Companions: [`../portability-analysis.md`](../portability-analysis.md) (feasibility),
> [`../postgres-implementation-plan.md`](../postgres-implementation-plan.md) (the phased runbook).

## Run it

```bash
cd docs/ai/plans/postgres-portability-poc
npm ci               # pulls kysely only (isolated package.json + pinned lockfile)
node list-read.mjs       # DocumentRepository.list() — the hot read path
node saveDraft-write.mjs # documents.saveDraft() — the hardest write path
```

Compile-only: uses Kysely's `DummyDriver` + each dialect's `QueryCompiler`.
No database connection, no Postgres install — it prints the compiled SQL +
bound params for both dialects side by side. `kysely` is pinned to `0.27.6` with a
committed lockfile: the printed SQL *is* the evidence, so it has to be reproducible.

## Why these two paths

- **`list()`** = the single read chokepoint (R4). Every list API/admin table goes through it.
- **`saveDraft()`** = the hardest write: `.batch()` atomicity, the `COALESCE(MAX)+1`
  version subquery (R6), the R5 hand-counted 27-bind `INSERT`, a prune `DELETE`
  with `NOT IN (… LIMIT ?)` subqueries, and the dynamic multi-row derived-facet
  `INSERT` chunked against D1's 100-bind cap (`document-projection.ts`).

If both port cleanly, the rest of the 764 `.prepare()` sites are strictly easier.

## Findings

### 1. Placeholder rewrite — **FREE**
`?` (SQLite) ↔ `$1..$N` (Postgres) handled entirely by the dialect compiler.
This was a whole "medium" line item in the original estimate — it evaporates.

### 2. Booleans — **isolated to one mapper**, not a repo-wide edit
SonicJS stores `is_published`/`is_current_draft`/`visible` as `0/1` integers.
`postgres-implementation-plan.md` §2 **keeps 0/1 integer columns on PG**, so the
hundreds of `= 1` comparisons need *zero* change and no mapper at all — the spike
prints that build first. If PG ever gets real `boolean` columns instead, a single
`bool()` helper flips the representation per-dialect:

```
SQLite : "is_published" = ?     params:[1]
Postgres: "is_published" = $3    params:[true]
```

One helper injected at the value boundary — not 300 hand-edits.

### 3. The `p`/alias string-prefix hack — **deleted**
`list()` today concatenates a `'d.'` string prefix when it joins facets. Kysely
resolves the `documents as d` alias itself, so that entire branch disappears.

### 4. Dynamic identifiers (`q_*` cols, sort column) — **`sql.ref()`**, guard kept
Generated-column filter/sort names are quoted per-dialect by `sql.ref()`. The
existing `SAFE_IDENTIFIER` regex stays as defense-in-depth.

### 5. The R5 27-bind INSERT — **the bug class is deleted**
The raw `saveDraft` INSERT carries this comment:

> `R5 arithmetic — keep balanced: 30 columns = 5 leading '?' + 1 version_number subquery + 3 literals + 21 trailing '?'. Total placeholders 27 MUST equal the 27 .bind() args.`

Kysely's named `values({ col: value })` form — with the version subquery as just
another named value — removes positional counting entirely. The `COALESCE(MAX)+1`
correlated subquery (R6) stays in SQL, standard in both dialects:

```
values (?, ?, …, (select coalesce(max(version_number), 0) + 1 from "documents" where "root_id" = ?), …)
```

**Scope of this win:** it covers *fixed-column* statements (the 30-column INSERT, the
13-bind UPDATE). It does **not** cover the dynamic multi-row derived-row inserts in
`document-projection.ts`: Kysely's `values([...])` array form emits one placeholder
tuple per row, so the *row* count is still a bind budget you own by hand —
**D1 caps at 100 params/statement (hard), Postgres at 65535**. Statement 4 in
`saveDraft-write.mjs` compiles that chunking (11 tag facets x 10 cols -> 9+2 rows,
90 + 20 binds) and asserts the budget, on both dialects.

### 6. `.batch()` → `.transaction()` on PG/SQLite, but **D1 needs a compile-and-batch shim**
On Postgres / better-sqlite3 / libSQL, the batch becomes
`db.transaction().execute(trx => …)` — real interactive transactions.

**Cloudflare D1 does not have transactions, and `kysely-d1` does not emulate them.**
`kysely-d1@0.4.0` `dist/index.js:95-110` — `beginTransaction` / `commitTransaction` /
`rollbackTransaction` each `throw new Error('Transactions are not supported yet.')`, so
`db.transaction()` fails at runtime on Workers. D1's only atomic primitive is `.batch()`.

Preserving R1/R7 atomicity on the CF flagship therefore needs a small shim (~1 file):
compile each builder and hand the statements to D1.

```ts
const stmts = queries.map((q) => {
  const { sql, parameters } = q.compile()
  return env.DB.prepare(sql).bind(...parameters)
})
await env.DB.batch(stmts) // one implicit transaction, rolls back as a unit
```

Statement **order** still matters (demote before insert, so the partial unique index never
sees two current drafts mid-batch) — same constraint as the raw version. Budget this shim
+ its atomicity test as explicit work in any Kysely adoption; it is **not** free.

### 7. `json_extract` is **NOT** in either chokepoint
`list()` filters pre-materialized `q_*` generated columns, not inline JSON.
`grep json_extract document-repository.ts` = **0**. The 38 `json_extract` sites
that genuinely need per-dialect `sql\`\`` fragments live in a **bounded 20-file
set** (scalar-schema DDL generator, projection, media-documents, a few plugins) —
enumerable, not pervasive.

## What Kysely does NOT solve (still hand-written, per dialect)

| Concern | Why it stays manual |
|---|---|
| `json_extract` ↔ `data->>'x'` / `jsonb` (38 sites) | dialect JSON semantics differ; write `sql\`\`` fragments |
| `VIRTUAL` generated columns (`document-scalar-schema.ts`) | Postgres has no `VIRTUAL`; branch to `STORED` **or** a native JSONB expression index |
| Partial/expression UNIQUE indexes | *already* portable — Postgres supports them natively (near-free) |
| **Batch atomicity on D1** | `kysely-d1` throws on `.transaction()`; needs a compile-and-batch shim over `env.DB.batch()` (finding 6) |
| **Multi-row bind budgeting** (`document-projection.ts`) | `values([...])` still emits one tuple per row — chunk by hand against D1's 100-param cap (finding 5) |

## Effort re-read (vs `portability-analysis.md`)

Kysely does not slash the raw week-count — it **changes the risk profile**:

- ~**764 `.prepare()` sites / 106 files** (re-counted 2026-10-20, excluding tests) → mechanical, *typed*, dual-dialect conversion (compiler catches column typos the raw strings can't).
- The genuinely-hard dialect SQL is confined to **20 files** of `json_extract` + **1** DDL generator branch.
- Bonus: Kysely *compiles* to **D1** (`kysely-d1`), **better-sqlite3**, **libSQL/Turso**, and **Postgres** from one query layer — the CF flagship, the Turso tier, and the PG tier share code. Caveat: on D1 only the compiler is reusable; the batch shim from finding 6 replaces `.transaction()`.

**Estimate:** ~**7–10 weeks** for full Postgres parity + a dual-dialect test matrix —
the bottom-up phase roll-up in [`../postgres-implementation-plan.md`](../postgres-implementation-plan.md) §11,
which this spike does not shorten. (An earlier draft of this README said 5–9 wk; that
number predated the D1 compile-and-batch shim in finding 6 and the chunked derived-row
work in finding 5.) What Kysely buys is **risk**, not weeks: roughly half the defect
exposure of a raw hand-written SQL port, typed and compiler-checked.

## Recommended sequencing

**Kysely is a quality track, not the critical path.** `postgres-implementation-plan.md` §9
ships Postgres via the `D1Database`-compatible driver shim + per-dialect helpers first —
faster, and it leaves the 764 `.prepare()` sites alone. Adopt Kysely *incrementally after
PG GA*, in this order:

1. Land the compile-and-batch shim over `env.DB.batch()` + a mid-batch-failure atomicity
   test (finding 6). Nothing else can move before this — D1 has no transactions.
2. Port `DocumentRepository` (read chokepoint) to Kysely, compiling to **D1 first** — no
   behavior change, CF stays green.
3. Port `DocumentsService` (writes), including the chunked derived-row inserts with their
   bind-budget assertions (finding 5).
4. Branch the 20 `json_extract` files to per-dialect `sql\`\`` fragments.
5. Add the Postgres dialect + swap the `q_*` `VIRTUAL` generator to `STORED` /
   JSONB expression indexes.
6. Stand up the real-Postgres test harness alongside `better-sqlite3` (R10).
