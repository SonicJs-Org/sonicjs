# Lexical FTS5 Search — Implementation Plan **v2** (sonicjs-org)

> v2 supersedes `SEARCH-FTS5-PLUGIN-PLAN.md` after a code-level reality check against this worktree
> (`worktree-search-fts5-plugin`, branched off `origin/main`). Every change below is backed by a
> file:line citation in the **Reality-check ledger** (end of doc). Read that ledger before building —
> v1 contained one runtime-breaking bug (bm25 arity), one silent-coverage bug (missing the default
> edit path), one unscoped subsystem (plain-text extraction), and a head-on route collision with a
> plugin that already exists. Companion background: `SEARCH-FTS5-PLUGIN-HANDOFF.md`.
> Task format: **Goal / Files / Change / Tests / Done-when**.

## Locked decisions (follow Lane — unchanged from v1)

1. **Lexical FTS5 is the base.** BM25 + snippet + highlight + `porter unicode61 remove_diacritics 2`,
   zero AI cost. Vector/analytics/experiments are separate future plugins.
2. **Indexing rides the document write-time projection** (a core seam in `DocumentProjection` /
   `DocumentsService`), NOT route hooks — hooks fire only from `api-content-crud.ts`; admin + media
   writes would be missed. This is the accepted "small core touch." **Verified correct** (see L1).
3. **Serving + engine + config** is the removable part. But it is **not** a brand-new `/api/search`
   plugin — that route is already owned (see Decision 6). It reconciles with the existing plugin.
4. **One index, `documents_fts`**, keyed by `document_id`; content + media unified — **subject to the
   media write-path read-flip landing first** (see T0.4, L5). Until then media is a documented gap.
5. Conform to document-model rules R1–R12.

### NEW locked decisions (forced by the reality check)

6. **The lexical engine plugs into the existing `ai-search-plugin`, it does not replace or shadow it.**
   `ai-search-plugin` already `definePlugin`s and already mounts `POST /api/search` +
   `GET /api/search/suggest`, with modes `'ai' | 'keyword'` (L2). Mounting a second `/api/search` is a
   route collision. **The FTS5 engine becomes the backend of the existing `keyword` mode** (today that
   mode is a `content.title/slug/data LIKE ?` scan over the **legacy `content` table** — L3). This also
   reuses the orchestrator the v1 handoff wrongly believed was absent.
7. **`documents_fts` is exactly the spike's 10-column layout** — no extra columns in the indexed/weighted
   path. Adding columns shifts the bm25 weight vector and breaks the verbatim engine port (L4).
   Soft-delete/visibility is kept out of the index at **write time** (a soft-deleted or `visible=0` row is
   deindexed, not inserted) so the public filter stays `is_published=1 AND tenant_id=?` — **native, no JOIN**,
   exactly as Lane specifies (LA2). The query-time JOIN to `documents` is the *fallback* only if write-time
   deindex proves insufficient (T1.1, L6).
8. **Plain-text extraction is a first-class task, not a sub-bullet** (T0.3). sonicjs-org has no
   `toPlainText` / field-type text registry (L7).

---

## Phase 0 — Core: schema + projection seam + text extraction

### T0.1 — `documents_fts` virtual table migration `[S]`
- **Goal:** the one FTS5 index, schema-matched to the spike for relevance parity.
- **Files:** `packages/core/migrations/0003_documents_fts.sql` (0003 is next free — only 0001/0002 exist,
  L8); `cd packages/core && npm run generate:migrations`; re-sync `my-sonicjs-app/migrations/`
  (byte-identical); commit regenerated `src/db/migrations-bundle.ts` — **R9**.
- **Change — use the spike's EXACT 10-column layout (not v1's 11):**
  ```sql
  CREATE VIRTUAL TABLE documents_fts USING fts5(
    title, slug, body,                                  -- indexed cols 0,1,2
    document_id UNINDEXED, type_id UNINDEXED, status UNINDEXED,
    created_at UNINDEXED, updated_at UNINDEXED, tenant_id UNINDEXED, is_published UNINDEXED,
    tokenize='porter unicode61 remove_diacritics 2'
  );
  ```
  **10 columns total** (3 indexed + 7 UNINDEXED). This is the spike's measured-parity schema and matches
  infowall `content_fts` column count, so the engine's `bm25(documents_fts, w0..w9)` 10-weight vector
  maps 1:1 (L4). **Do NOT add `root_id` to the FTS table** (v1's bug — it makes 11 columns and the ported
  10-weight bm25 call throws "wrong number of arguments to function bm25()"). `root_id` is not needed in
  the index: results JOIN back to `documents` on `document_id` to fetch `root_id`/`deleted_at`/`visible`.
  Virtual table lives only in the raw migration — **R2**.
- **FTS5 schema-evolution note:** FTS5 has no `ALTER TABLE ADD COLUMN`. Any future column change = a new
  migration that drops + recreates `documents_fts` + a backfill (T0.5). It does **not** go through
  `ensureDocumentGeneratedColumns` (that is for `q_*` generated columns on `documents`, not virtual tables).
- **Tests:** real-DB sqlite (**R10**): table creates; accepts insert; `MATCH` returns rows; a
  `bm25(documents_fts, 5,2,1,0,0,0,0,0,0,0)` (10 weights) call executes without arity error.
- **Done when:** migration applies; bundle regenerated + committed; `my-sonicjs-app` copy byte-identical;
  bm25 arity test green.

### T0.2 — FTS projection in `DocumentProjection` (the seam) `[M]`
- **Goal:** every document write (de)indexes `documents_fts` atomically, with universal coverage across
  **all** write paths.
- **Files:** `packages/core/src/services/document-projection.ts`, `packages/core/src/services/documents.ts`.
- **Change:**
  - Add `buildFtsInsertStatements(doc, searchableText, now)` + `buildFtsDeleteStatements(documentId)` to
    `DocumentProjection`, returning raw D1 prepared statements (same synchronous shape as
    `buildDerivedInsertStatements`/`buildDerivedDeleteStatements`, L9). `title`/`slug` come from the
    document **columns** (`doc.title`, `doc.slug`), **not** from `data` (L10). `body` = the extracted
    plain text from T0.3.
  - **Fold the FTS statements next to the existing `buildDerived*` calls at EVERY mutation site. The
    complete, corrected list (v1 mislabeled `updateInPlace` as `publish` and omitted it — L11):**

    | Method | Lines (current) | FTS action |
    |---|---|---|
    | `create` | insert :145 | insert |
    | `saveDraft` (versioned / published path) | delete :211, insert :239 | delete prev (if not published) + insert new |
    | **`updateInPlace` (DEFAULT edit path — versioning off & not published)** | delete :306, insert :307 | **delete + insert — MISSING in v1** |
    | `publish` | delete :343 (hard-delete branch), delete :353 (clear-publish branch), insert :368 | mirror each |
    | `unpublish` | delete :397 | delete (if not current draft) |
    | `erase` | inline loop :432–435 | add `DELETE FROM documents_fts WHERE document_id = ?` per id |
    | **`softDelete`** | :408 (no derived mutation today) | **add an FTS delete** — deindex the row (Lane-aligned: keeps deleted rows out of the index so the public filter needs no JOIN, LA2). softDelete is one-way (no restore path in `documents.ts` — L28b), so no re-index is needed. |

  - **Write-time visibility rule (LA2):** `buildFtsInsertStatements` emits a row **only when**
    `deleted_at IS NULL AND visible = 1`; for a soft-deleted or hidden row it emits the **delete only**. So
    every write path naturally keeps the index to visible, live rows — `is_published`/`tenant_id` then filter
    natively at query time with no JOIN (Decision 7). `visible` toggles back via `updateInPlace`/`saveDraft`,
    which already reindex, so un-hiding re-inserts for free.

    ⚠️ `updateInPlace` is reached from `saveDraft` (:201–203) whenever `versioning` is off — and
    `versioning` **defaults to false** (:80). It is the most common authoring path. Indexing only the
    `saveDraft` branch (v1) silently skips reindex on nearly all real edits.
  - **R1** (raw batch), **R3** (tenant-scoped — FTS rows carry `tenant_id`), **R5** (count binds by hand:
    the insert binds exactly 10 values for 10 columns).
  - **Transient-retry (reworded — v1's wording was impossible):** `retryTransientD1` does **not** exist in
    sonicjs-org core; it lives inside infowall's `fts5.service.ts` and ports with the *engine* (T1.2). The
    FTS inserts are folded into the **same atomic `db.batch([...])`** as the document write, so you cannot
    retry "just the FTS write." Decision: **wrap the existing `this.db.batch(...)` calls in
    `DocumentsService` with a `retryTransientD1` helper extracted into core** (e.g.
    `services/d1-retry.ts`). Acknowledge the blast radius — this changes retry behavior for **all**
    document writes, not only FTS (arguably an improvement; call it out for review). If that blast radius
    is not wanted now, ship without retry and file a follow-up; do **not** claim a per-FTS retry that the
    batch shape makes impossible (L12).
- **Tests:** real-DB sqlite (**R10**), one case per path: create→searchable; **`updateInPlace`→old text
  gone, new present** (the path v1 missed); saveDraft supersede→same; publish/unpublish→`is_published`
  column correct; erase→row removed; multi-field bm25 ordering with 10 weights.
- **Done when:** all SIX write paths (incl. `updateInPlace`) index/deindex atomically; default-config
  edits (versioning off) reindex.

### T0.3 — Searchable-field declaration + text extraction `[M]` — **NEW (was an unscoped one-liner in v1)**
- **Goal:** declare *which* per-type fields are full-text and turn their `data` JSON into the plain text
  indexed into `body`. The text subsystem **does not exist** in sonicjs-org (no `toPlainText`, no field-type
  text registry — L7); `extractPath` only reads top-level `$.<key>` and returns raw values, not text (L13).
- **Lane alignment (LA1):** Lane's direction is that "which fields are full-text" stays **declarative via the
  document type's `queryable_fields` — the same mechanism scalar/facet fields use" — not hard-coded and not
  a separate parallel config. v1 tried to reuse the existing facet field set (wrong: kinds are
  `scalar|facet|reference`, no fulltext kind — L14). v2 honors Lane by **extending the mechanism**, not
  bypassing it.
- **Files:** `packages/core/src/schemas/document.ts` (extend `QueryableFieldKind`),
  `packages/core/src/services/searchable-text.ts` (new).
- **Change (two parts):**
  - **Declaration (Lane-aligned):** add `'fulltext'` to `QueryableFieldKind`
    (`'scalar'|'facet'|'reference'|'fulltext'`) with an optional per-field `weight?: number` (feeds the bm25
    boost). A document type lists its body fields as `kind:'fulltext'` in `queryableFields` — identical
    plumbing to scalar/facet, so it rides the existing per-type registration and the `reindexType` path. The
    projection routes `'fulltext'` fields to the FTS `body` slot (the `// 'scalar' fields are VIRTUAL` branch
    in `buildDerivedInsertStatements` gets a `'fulltext'` sibling). `title`/`slug` are always indexed from the
    document **columns** regardless (L10).
  - **Extraction:** `searchable-text.ts` — a self-contained recursive harvester (port infowall's
    `extractSearchableText` shape): walk a field value (depth ≤ 5), collect string leaves, strip HTML
    (`replace(/<[^>]*>/g, ' ')`), join Quill Delta `{ops:[...]}` `op.insert` strings, skip URLs/UUIDs/very
    short strings, collapse whitespace. No field-type registry dependency. Used to render each `'fulltext'`
    field’s value to plain text before it enters `body`.
  - **Fallback:** if a type declares **no** `'fulltext'` fields, index `title`/`slug` only (still
    searchable) and optionally harvest a conventional `body`/`content`/`description` key — but prefer the
    explicit `kind:'fulltext'` declaration so indexing is intentional, per Lane.
- **Tests:** a type with `kind:'fulltext'` body field → prose indexed; Delta JSON → joined; HTML → stripped;
  nested object → leaves harvested; URL/UUID/id excluded; type with no fulltext fields → title/slug-only row.
- **Done when:** `buildFtsInsertStatements` consumes declared `'fulltext'` fields for `body`; a rich-text doc
  indexes readable prose, not JSON punctuation; declaration rides `queryableFields` (no parallel config).

### T0.4 — Media coverage gate `[S]` — **NEW (v1 over-claimed media is searchable)**
- **Goal:** be honest about media-in-search; don't claim unified content+media until it's true.
- **Reality:** `MediaDocumentService.create` goes through `DocumentsService` (so it *would* be indexed),
  **but the live upload routes still `INSERT INTO media` (legacy table), bypassing `DocumentsService`** —
  `api-media.ts:148`, `api-media.ts:302`, `admin-media.ts:356` (L5). Media uploaded through the real admin
  UI / API is therefore **not** written as a document and **not** indexed.
- **Change:** do **not** add media-specific FTS logic. Gate media-in-search on the media write read-flip
  (CLAUDE.md status: "in progress, slice 3"). Until upload routes write via `DocumentsService`, scope
  search to content document types and state media is a known gap in the Review section. When the read-flip
  lands, media indexes for free (it's just another `document_type`).
- **Done when:** plan + tests scope to content types; media gap documented; no false "unified" claim.

### T0.5 — Backfill / self-heal existing documents `[S]`
- **Goal:** populate `documents_fts` for docs written before the seam (and after any FTS schema rebuild,
  per T0.1's no-ALTER note).
- **Files:** `scripts/backfill-fts.ts` (preferred over bootstrap self-heal — keeps a full table scan off
  the request path; bootstrap runs on first request).
- **Change:** idempotent pass over `(is_current_draft=1 OR is_published=1) AND deleted_at IS NULL` rows
  (mirror `DocumentProjection.reindexType`'s row-selection, L15) missing from `documents_fts`. Batched
  (≤20 docs/batch, the existing reindex chunk size). Reuse `searchable-text.ts`.
- **Tests:** seed docs pre-index → backfill → all searchable; re-run is a no-op; rebuild-after-drop works.

---

## Phase 1 — Engine + serving (reconciled with the existing plugin)

### T1.1 — Port the FTS5 query engine `[M]`
- **Goal:** BM25 search over `documents_fts` with snippet/highlight, Unicode-safe sanitizing, and
  correct visibility/soft-delete filtering.
- **Files (new):** `packages/core/src/plugins/core-plugins/ai-search-plugin/services/fts5-engine.ts`,
  `.../services/fts5-sanitize.ts`.
- **Change:**
  - Port infowall `fts5.service.ts` re-pointed: `content_fts`→`documents_fts`, `content_id`→`document_id`,
    `collection_id`→`type_id`, the `status IN (...)` filter stays. infowall uses **one** `content_fts`
    table (not N per-collection — L16), so this is largely a rename, **except**: infowall searched
    `content_fts` and `media_fts` as two paths; unifying into one `documents_fts` collapses that to one
    query (simpler, but verify the media path isn't lost — tied to T0.4).
  - Port `fts5-sanitize.ts` **verbatim** — it is 76 lines, zero imports, fully self-contained (L17). ✅
  - **bm25:** keep the 10-weight call `bm25(documents_fts, ${titleBoost}, ${slugBoost}, ${bodyBoost},
    0,0,0,0,0,0,0)` — exactly 10 weights for 10 columns (L4).
  - **Visibility + soft-delete — native, no JOIN (Lane-aligned, LA2; fixes L6/L18):** because the write
    path deindexes soft-deleted/`visible=0` rows (T0.2's write-time visibility rule), the index only ever
    holds visible, live rows, so the query stays JOIN-free exactly as Lane requires:
    ```sql
    SELECT ... bm25(documents_fts, ${titleBoost}, ${slugBoost}, ${bodyBoost}, 0,0,0,0,0,0,0) AS score
    FROM documents_fts fts
    WHERE documents_fts MATCH ?
      AND fts.tenant_id = ?
      AND fts.is_published = 1        -- public; admin surface uses is_current_draft semantics instead
      AND fts.type_id IN (...)
    ```
    v1's "no JOIN, visibility native" was *unsafe* only because v1 never deindexed soft-deletes; with the
    write-time rule it is both safe and JOIN-free. **Fallback:** if write-time deindex proves leaky in
    practice, add a `JOIN documents d ON d.id = fts.document_id` with `d.deleted_at IS NULL AND d.visible = 1`
    — but that costs a JOIN Lane explicitly wanted to avoid, so prefer the write-time rule.
  - **Result row-selection / dedup (NEW, L19):** a root with a published row **and** a divergent current
    draft has **two** `documents_fts` rows. Public search filters `is_published=1`; admin search filters
    `d.is_current_draft=1`. An unfiltered "all" query must `GROUP BY fts.document_id`→root or it returns the
    root twice. Specify which axis each surface uses.
  - **DELETE cost note (L20):** `DELETE FROM documents_fts WHERE document_id = ?` scans the FTS table
    (document_id is an UNINDEXED nanoid). Fine at POC scale; revisit (rowid mapping) if the index grows large.
- **Tests:** sqlite parity-style: stemming (`run`→running), diacritics (`cafe`→café), field-boost order,
  prefix match, **soft-deleted doc excluded**, **visible=0 excluded**, **no duplicate root when
  draft≠published**. **R10**.

### T1.2 — Wire FTS5 as the `keyword` mode of the existing `ai-search-plugin` `[M]` — **REframed**
- **Goal:** serve lexical results through the route that already exists, no collision, no second engine.
- **Files:** `packages/core/src/plugins/core-plugins/ai-search-plugin/services/ai-search.ts` (the
  orchestrator — modes `'ai'|'keyword'`, L2), `.../routes/api.ts`.
- **Change:** replace the `keyword`-mode backend (today: `content.title/slug/data LIKE ?` over the legacy
  `content` table — L3) with `fts5-engine.ts` over `documents_fts`. AI mode is untouched and still degrades
  cleanly when `c.env.AI`/`VECTORIZE_INDEX` are absent (they are — not in `wrangler.toml` and not in the
  `Bindings` interface; the plugin reads them via `as any` — L21) → orchestrator already falls back to
  keyword (L22), which now means lexical FTS5 (the desired "AI degrades to lexical floor").
  - KV result cache: port infowall `search-cache.service.ts` on `CACHE_KV` (exists — L23). Key = SHA-256
    hex prefix of normalized `{q, mode, limit, offset, filters}`. Invalidate via `invalidateAll()` on
    settings save.
  - Public route principal `[{type:'public',id:'*'}]`, `is_published=1` (no published-only fast path — D5).
    Escape rendered output — **R8**.
  - **If a clean-room separate plugin is preferred over editing `ai-search-plugin`:** it must mount a
    **different** path (e.g. `/api/lexical-search`) and the relationship documented — but reusing the
    existing orchestrator is recommended (it *is* the mode registry the handoff wanted).
- **Tests:** integration route test: `mode:'keyword'` returns ranked FTS hits; cache hit path; published-only
  filtering; AI-mode-with-no-bindings falls back to FTS5 keyword.

### T1.3 — Admin config UI + settings persistence `[M]` — **persistence corrected**
- **Goal:** lexical settings (bm25 weights, results limit, cache TTL, which types searchable).
- **Files:** `.../ai-search-plugin/components/settings-page.ts` (exists) or a new
  `.../services/fts-settings.service.ts`; declarative `menu` + `configSchema`.
- **Change — DO NOT assume the `plugins` table (v1's note was contradictory, L24):** `plugins` is declared
  in `db/schema.ts:214` but is **NOT created by any raw migration** (0001 has 11 `CREATE TABLE`s, none
  `plugins`; 0002 = the 5 document tables). On a greenfield D1 the table doesn't exist, so
  `EmailSettingsService`/`ai-search` settings reads hit their `catch`→return empty (L25). "Mirror
  email-plugin" therefore mirrors a **non-functional** read. Pick a real mechanism:
  - **Recommended:** persist settings in **`CACHE_KV`** under a fixed key (`fts-search:settings:v1`) — the
    binding exists, no migration, and cache-invalidation already lives there.
  - **Or** a `plugin_settings` **document type** (doc-model-consistent, no new table — matches "document
    model is the data model").
  - **Or** add `plugins` to a raw migration (`0004_*`) if the project wants the relational table — but that
    is a broader decision touching every plugin; don't make it unilaterally here.
- **Tests:** settings round-trip through the chosen store; weight change reflected in ranking; cache
  invalidated on save.

---

## Phase 2 — Validation

### T2.1 — E2E + relevance sanity `[M]`
- **Files:** `tests/e2e/82-fts5-search.spec.ts` — **next free is 82, not 68** (highest existing spec is
  **81**; v1's 68 and CLAUDE.md's "floor 68 / highest 67" are stale — L26). **R11.**
- **Change:** Playwright: create content via admin → searchable; **edit it (default versioning-off
  `updateInPlace` path) → updated text searchable, old text gone** (guards the v1-missed path); query via
  the existing `/api/search` `keyword` mode returns ranked highlighted results; draft excluded from public
  search; soft-deleted/hidden excluded. (Media included only if T0.4's read-flip has landed.)
- **Optional:** small BEIR-style relevance check if datasets are handy.
- **Done when:** E2E green; `npm test` + `cd packages/core && npm run type-check` + lint clean.

---

## Out of scope (future add-on plugins)
- **AI/vector search** — already partially present in `ai-search-plugin` (Cloudflare AI Search/RAG,
  embeddings, chunking) but **dormant** (no `AI`/`VECTORIZE_INDEX` bindings). v2 does **not** build it; it
  reuses that plugin's *shell* and makes its `keyword` mode real. Enabling AI mode = wiring bindings +
  the `ai_search_index_meta`/`ai_search_history` tables (which currently have **no migration** — L27).
- **Analytics / experiments / query-enhancement** — separate plugins; compose the lexical base.

## Sequencing
Phase 0 serial: T0.1 → T0.3 (text extraction) → T0.2 (seam consumes it) → T0.4 (media gate) → T0.5
(backfill). Phase 1 fans out after T0.1 (engine builds against the schema) but T1.2 (route wiring) must
wait for the reconciliation decision in Decision 6. Phase 2 last. Every task keeps core suite + tsc + lint
green; **R10** real-DB coverage is mandatory.

---

## Lane-direction alignment ledger (`INFOWALL-SEARCH-FOR-SONICJS-PLUGIN.md`)

Checked v2 against Lane's locked direction doc (in the infowall repo). v2 is faithful on the load-bearing
rules; two divergences were reconciled *toward* Lane (LA1/LA2), three are conscious deferrals consistent
with the handoff's greenfield reframing (LA3/LA4/LA5).

| ID | Lane's direction | v2 status |
|---|---|---|
| **LA0** | `documents_fts` tokenizer + title/slug/body layout matched so the bm25 weight vector maps 1:1 (§4). | ✅ **v2 enforces it; v1 violated it.** v2's 10-col fix (C2/L4) is literally Lane's parity requirement — v1's extra `root_id` broke the 1:1 Lane locked. |
| **LA1** | "Which fields are full-text" stays declarative via the document type's **`queryable_fields` — the same mechanism scalar/facet fields use," not hard-coded. | ✅ **reconciled** — T0.3 now adds `kind:'fulltext'` to `QueryableFieldKind` (extends the existing mechanism) instead of v2-draft's separate `searchableFields` array. Honors Lane's "same mechanism." |
| **LA2** | Visibility/tenancy **native — no content-table JOIN**; rides `is_published`/`tenant_id` on the projection (§4). | ✅ **reconciled** — kept JOIN-free by deindexing soft-deleted/`visible=0` rows at write time (Decision 7, T0.2, T1.1). v2-draft's query-time JOIN demoted to fallback. (Lane's spike didn't model soft-delete; this preserves his no-JOIN intent.) |
| **LA3** | The **mode registry** (§6b) is the primary seam — core self-seeds `fts5`; plugins register modes; `ctx.fts5` composition; absent mode → fts5 floor. | ✅ **decided from code — do not build it now.** sonicjs-org has **no** mode-registry seam: the orchestrator dispatches on a hardcoded `mode:'ai'\|'keyword'` if/else (L29), and AI mode is dormant (no `AI`/`VECTORIZE_INDEX` bindings — L21). The code's intent is a two-mode orchestrator, not a registry. **Decision:** wire FTS5 as the `keyword` backend now; the registry is YAGNI until a second engine exists. **Revisit trigger (self-evident from code, no sign-off needed):** the day `AI`/`VECTORIZE_INDEX` bindings are added and AI mode goes live, refactor the if/else into a registry (register `fts5`/`ai`/`hybrid`, pass `ctx.fts5`) as the same PR that enables AI. |
| **LA4** | **Degrade contract:** `mode=ai/hybrid` with no AI plugin resolves to the FTS5 floor with a `degraded:true` flag; core never breaks. | ⚠️ **partial** — the orchestrator already falls back keyword-when-AI-absent (L22), but sets **no `degraded` flag** (L30). v2 should add the flag when AI mode resolves to lexical, to honor the contract. Cheap; do it in T1.2. |
| **LA5** | Validate relevance with **BEIR (pytrec_eval)** — the FTS5 leg should match published BM25; the neutrality gate when re-pointing onto `documents_fts`. | ⚠️ **de-emphasized** — v2 T2.1 keeps BEIR optional because the spike already measured byte-identical parity to the live engine. Reasonable for a port, but note Lane treats BEIR as *the* gate; run it if the engine diverges from a clean re-point. |
| **LA6** | Keep lexical engine free of AI cost; analytics/experiments separate plugins; content+media one index. | ✅ aligned (media gated on the write read-flip — T0.4/L5, a sonicjs-org reality Lane's doc assumed already done). |

## Reality-check ledger (evidence for every v2 change)

| ID | Finding | Evidence | Severity |
|---|---|---|---|
| **L1** | Indexing-at-projection (not hooks) is correct: admin-content + media writes dispatch no hooks; hooks fire only from `api-content-crud.ts`. | handoff §4; `documents.ts` write paths | ✅ keep |
| **L2** | An `ai-search-plugin` **already exists** and **already mounts `POST /api/search` + `GET /api/search/suggest`**, modes `'ai'\|'keyword'`. v1 treated AI search as non-existent future scope → route collision. | `ai-search-plugin/index.ts` `register()`; `routes/api.ts`; `types.ts:33` | 🔴 critical |
| **L3** | Existing `keyword` mode scans the **legacy `content` table** (`c.title/slug/data LIKE ?`, `collection_id` ints), not `documents`. | `ai-search.ts:318,369,385` | 🔴 critical |
| **L4** | bm25 arity: infowall `content_fts`=10 cols, `bm25(content_fts, …)` passes **10 weights**; spike `documents_fts`=10 cols. v1 added `root_id`→**11 cols**; a 10-weight ported bm25 call throws "wrong number of arguments". | infowall `101_fts5_denormalize.sql:17-29`, `fts5.service.ts:213`; spike Q1; v1 plan T0.1 | 🔴 critical |
| **L5** | Media uploads still `INSERT INTO media` (legacy) via the live routes, bypassing `DocumentsService` → not indexed. v1 claimed media is searchable. | `api-media.ts:148,302`, `admin-media.ts:356`; `media-documents.ts:148` | 🔴 critical |
| **L6** | FTS table has no `deleted_at`/`visible`; v1 said "no JOIN, visibility native" → soft-deleted/hidden docs leak. | proposed schema; `documents.ts:408` (`softDelete` clears nothing) | 🟠 high |
| **L7** | No `toPlainText` / field-type text registry exists in core. infowall has a whole subsystem (`fieldTypeRegistry.toPlainText`, `deltaToPlainText`, recursive `extractSearchableText`). | grep `toPlainText` in core = 0 hits; infowall `fts5.service.ts:764-850` | 🔴 critical |
| **L8** | `0003` is next free (only 0001/0002 exist). ✅ | `packages/core/migrations/` | ✅ keep |
| **L9** | Derived builders are synchronous and return `D1PreparedStatement[]` — FTS builders can mirror them. | `document-projection.ts:46-132` | ✅ pattern |
| **L10** | `title`/`slug` are top-level document columns (`doc.title`/`doc.slug`), not `data` fields; `body` is in `data`. | `documents.ts:24-57` | 🟠 high |
| **L11** | v1's fold-in list mislabeled `updateInPlace`'s `:306` as "publish" and omitted `:307`; `updateInPlace` is a **distinct** path. | `documents.ts:268-314` | 🔴 critical |
| **L12** | `retryTransientD1` not in core; FTS inserts are inside the document `db.batch` so a per-FTS retry is impossible — must wrap the whole batch (blast radius). | grep core = 0; infowall `fts5.service.ts:48-65`; `documents.ts:147,256,…` | 🟠 high |
| **L13** | `extractPath` supports only top-level `$.<key>`, returns raw values. | `document-projection.ts:171-178` | 🟠 high |
| **L14** | `QueryableFieldKind = 'scalar'\|'facet'\|'reference'` — no fulltext kind; can't reuse "the facet field set" for search. | `schemas/document.ts:6` | 🟠 high |
| **L15** | `reindexType` row-selection `(is_current_draft=1 OR is_published=1) AND deleted_at IS NULL` — backfill should mirror it. | `document-projection.ts:136-144` | ✅ pattern |
| **L16** | infowall uses **one** `content_fts` (not per-collection); `collection_id IN (...)` filter, no table interpolation → engine re-point is largely a rename. | infowall `fts5.service.ts:221-224` | ✅ keep |
| **L17** | `fts5-sanitize.ts` = 76 lines, zero imports — ports verbatim. ✅ | infowall `fts5-sanitize.ts` | ✅ keep |
| **L18** | `softDelete` clears no derived rows; with no FTS `deleted_at` column, deleted docs stay searchable. | `documents.ts:408-414` | 🟠 high |
| **L19** | Projection indexes both current-draft and published rows → up to 2 FTS rows per root; needs axis filter / dedup. | `documents.ts` publish/saveDraft paths | 🟡 medium |
| **L20** | `DELETE … WHERE document_id=?` on FTS = linear scan (UNINDEXED nanoid). | proposed delete | 🟡 medium |
| **L21** | No `AI`/`VECTORIZE` binding: `wrangler.toml` has DB/MEDIA_BUCKET/CACHE_KV/send_email only; `Bindings` interface omits them; plugin reads via `as any`. | `my-sonicjs-app/wrangler.toml`; `app.ts:80-83`; `ai-search/routes/api.ts:23-24` | ✅ keep |
| **L22** | Orchestrator already falls back keyword-when-AI-absent. | `ai-search.ts:271-298` | ✅ reuse |
| **L23** | `CACHE_KV` exists; search-cache ports; key = SHA-256 hex prefix; `invalidateAll()` by prefix. | `wrangler.toml`; infowall `search-cache.service.ts` | ✅ keep |
| **L24** | v1 said "(no `plugins` table)" but email/ai-search both `SELECT settings FROM plugins`. | `email-plugin/services/settings.service.ts`; `ai-search.ts:41` | 🟠 high |
| **L25** | `plugins` is in `db/schema.ts:214` but **no raw migration creates it** → empty on greenfield (reads fall to catch). Persistence genuinely unresolved (handoff OQ#1). | `schema.ts:214`; `0001_core.sql` (11 CREATE TABLEs, none `plugins`) | 🟠 high |
| **L26** | Highest existing E2E spec is **81**, not 67 → next free **82**; v1's `68-` and CLAUDE.md's "floor 68" are stale. | `tests/e2e/` listing | 🟡 medium |
| **L27** | `ai_search_index_meta` / `ai_search_history` referenced by the existing plugin have **no migration**. | `ai-search/services/indexer.ts:369`, `ai-search.ts:513`; migrations grep | 🟡 medium (existing-plugin debt) |
| **L28b** | `softDelete` is **one-way** — no restore/undelete path (`deletedAt: null` appears only in `create`). So deindex-on-softDelete needs no re-index counterpart. | grep `deleted_at = NULL`/`restore`/`undelete` = 0; `documents.ts:115` | ✅ enables LA2 |
| **L29** | **No mode-registry seam** in sonicjs-org — the orchestrator dispatches on a hardcoded `mode:'ai'\|'keyword'` if/else, not a registry (`registry.register` hits are the document-type registry). | `ai-search.ts:271-298`; grep `modeRegistry`/`EngineRequestContext` = 0 | ⚠️ LA3 deferral |
| **L30** | Orchestrator has **no `degraded` flag** — it falls back to keyword silently. | grep `degraded`/`degrade` in `ai-search.ts` = 0 | ⚠️ LA4 partial |

> **PR base — decided from git (no confirmation needed):** base on **`origin/main`**. `origin/main` is
> **13 commits ahead** of `origin/v3` and `origin/v3` is **0 ahead** (v3 strictly trails and only merges
> main in); the `v3.0.0-beta.3` release commits and the doc-model code are on main; this worktree is
> branched off main. So **main is the active v3 line** — CLAUDE.md's "work in `.conductor/hong-kong-v3/`,
> target `origin/v3`" guidance is stale for this checkout. `gh pr create --base main`.

---

## Implementation Review (2026-06-20 — built, local, NOT committed)

All tasks T0.1–T2.1 implemented. **type-check clean · lint 0 errors · ~50 new FTS tests green.**

### Shipped
**Core (new):** `migrations/0003_documents_fts.sql` (10-col layout), `services/searchable-text.ts`
(recursive HTML/Delta→text harvester), `services/d1-retry.ts` (transient-D1 retry). **Core (modified):**
`document-projection.ts` (`buildFtsUpsertStatements`/`buildFtsDeleteStatements` + FTS in `reindexType`),
`documents.ts` (FTS folded into all 7 write paths + batches wrapped in retry), `schemas/document.ts`
(`kind:'fulltext'` + `weight`), `db/migrations-bundle.ts` (regenerated), `__tests__/utils/d1-sqlite.ts`
(harness applies 0003). **Plugin (new):** `ai-search-plugin/services/fts5-engine.ts`, `fts5-sanitize.ts`
(verbatim), `fts-settings.service.ts` (KV), `fts-search-cache.ts` (KV). **Plugin (modified):**
`ai-search.ts` (keyword backend = FTS5, legacy `content LIKE` scan deleted, `degraded` flag, tenant +
KV), `routes/api.ts` (tenant + CACHE_KV), `routes/admin.ts` (GET/POST `/fts-settings`), `types.ts`.
**Scripts/tests:** `my-sonicjs-app/scripts/backfill-fts.ts`, 6 new `*.sqlite.test.ts`/unit suites,
`tests/e2e/82-fts5-search.spec.ts`.

### Decisions made from code (no check-backs)
- **Explicit FTS reprojection, not mirror-`buildDerived*`** (C2/T0.2): the mirror would leave
  `is_published` stale on publish (publish skips re-projection when the row is the current draft) →
  the native public filter would hide just-published docs. Reproject post-mutation state instead.
  Tested in `documents-fts-projection.sqlite.test.ts`.
- **FTS folded into `reindexType`** → backfill (T0.5) and the admin reindex both rebuild the index.
- **Retry wraps the whole document batch** (acknowledged blast radius — `d1-retry.ts` header).
- **Settings/cache in `CACHE_KV`** (LA-corrected): the `plugins` table has no greenfield migration, so
  the legacy settings read is a no-op — KV is the real store (`fts-settings.service.ts`).
- **`degraded:true`** set when an `ai` request falls back to the lexical floor (LA4).

### Known gaps / deferrals (intentional, documented)
- **Media not indexed yet** (T0.4): live upload routes still `INSERT INTO media` (legacy), bypassing
  `DocumentsService`. Indexes for free once the media write read-flip lands.
- **Body indexing per collection** requires the collection to declare a `kind:'fulltext'` queryable
  field; the engine + harvester are ready, but no demo collection declares one yet (E2E searches by
  title, which is always indexed). Adding `fulltext` to `blog_post`'s config would demo body search.
- **Admin config**: GET/POST `/fts-settings` endpoints + KV persistence are in and tested; a rich
  glass-morphism settings *form* is not wired into `settings-page.ts` (endpoint-backed; quick to add).
- **BEIR relevance harness** (LA5): not run — the spike already measured byte-identical parity.

### Pre-existing test failures (NOT from this work — verified via `git stash` baseline on clean main)
16 failures across 9 files fail identically on unmodified `origin/main`: the email-plugin suites (6),
`media-documents.test.ts`, `admin-content-docbacked.integration.test.ts`,
`api-content-crud-documents.integration.test.ts`. They are assertion failures unrelated to FTS (zero
`documents_fts` references). This work introduced 2 regressions (migration-count assertion + the rbac
test's inline harness), both fixed.
