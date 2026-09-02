# Postgres Portability — Kysely Spike (compile-only)

> Measures the real effort of a SonicJS → Postgres port by porting the two
> chokepoint code paths to **Kysely** and proving one TypeScript builder
> compiles to correct **SQLite (D1)** *and* **Postgres** SQL.
>
> **Status:** spike / measurement only. No production code changed.
> Companion to [`../portability-analysis.md`](../portability-analysis.md).

## Run it

```bash
cd docs/ai/plans/postgres-portability-poc
npm install          # pulls kysely only (isolated package.json)
node list-read.mjs       # DocumentRepository.list() — the hot read path
node saveDraft-write.mjs # documents.saveDraft() — the hardest write path
```

Compile-only: uses Kysely's `DummyDriver` + each dialect's `QueryCompiler`.
No database connection, no Postgres install — it prints the compiled SQL +
bound params for both dialects side by side.

## Why these two paths

- **`list()`** = the single read chokepoint (R4). Every list API/admin table goes through it.
- **`saveDraft()`** = the hardest write: `.batch()` atomicity, the `COALESCE(MAX)+1`
  version subquery (R6), the R5 hand-counted 27-bind `INSERT`, and a prune `DELETE`
  with `NOT IN (… LIMIT ?)` subqueries.

If both port cleanly, the rest of the 743 `.prepare()` sites are strictly easier.

## Findings

### 1. Placeholder rewrite — **FREE**
`?` (SQLite) ↔ `$1..$N` (Postgres) handled entirely by the dialect compiler.
This was a whole "medium" line item in the original estimate — it evaporates.

### 2. Booleans — **isolated to one mapper**, not a repo-wide edit
SonicJS stores `is_published`/`is_current_draft`/`visible` as `0/1` integers;
Postgres wants real `boolean`. In the spike a single `bool()` helper flips the
representation per-dialect:

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

### 6. `.batch()` → `.transaction()`
D1 `.batch([...])` maps to `db.transaction().execute(trx => …)`. On Workers the
`kysely-d1` dialect maps transactions back onto D1 batch semantics, so the CF
flagship keeps working from the same code.

### 7. `json_extract` is **NOT** in either chokepoint
`list()` filters pre-materialized `q_*` generated columns, not inline JSON.
`grep json_extract document-repository.ts` = **0**. The 38 `json_extract` sites
that genuinely need per-dialect `sql\`\`` fragments live in a **bounded ~20-file
set** (scalar-schema DDL generator, projection, media-documents, a few plugins) —
enumerable, not pervasive.

## What Kysely does NOT solve (still hand-written, per dialect)

| Concern | Why it stays manual |
|---|---|
| `json_extract` ↔ `data->>'x'` / `jsonb` (38 sites) | dialect JSON semantics differ; write `sql\`\`` fragments |
| `VIRTUAL` generated columns (`document-scalar-schema.ts`) | Postgres has no `VIRTUAL`; branch to `STORED` **or** a native JSONB expression index |
| Partial/expression UNIQUE indexes | *already* portable — Postgres supports them natively (near-free) |

## Effort re-read (vs `portability-analysis.md`)

Kysely does not slash the raw week-count — it **changes the risk profile**:

- ~**743 `.prepare()` sites / 100 files** → mechanical, *typed*, dual-dialect conversion (compiler catches column typos the raw strings can't).
- The genuinely-hard dialect SQL is confined to **~20 files** of `json_extract` + **1** DDL generator branch.
- Bonus: Kysely compiles to **D1** (`kysely-d1`), **better-sqlite3**, **libSQL/Turso**, and **Postgres** from one query layer — the CF flagship, the Turso tier, and the PG tier share code.

**Estimate:** ~**5–9 weeks** for full Postgres parity + a dual-dialect test matrix,
at roughly half the defect risk of a raw hand-written SQL port.

## Recommended sequencing (if Postgres is pursued)

1. Adopt Kysely as the universal query layer behind `DocumentRepository` /
   `DocumentsService`, compiling to **D1 first** — no behavior change, CF stays green.
2. Branch the ~20 `json_extract` files to per-dialect `sql\`\`` fragments.
3. Add the Postgres dialect + swap the `q_*` `VIRTUAL` generator to `STORED` /
   JSONB expression indexes.
4. Stand up the real-Postgres test harness alongside `better-sqlite3` (R10).
```
