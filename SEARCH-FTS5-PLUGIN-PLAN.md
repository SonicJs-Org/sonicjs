# Lexical FTS5 Search — Implementation Plan (sonicjs-org)

> Aligned to Lane's direction (`INFOWALL-SEARCH-FOR-SONICJS-PLUGIN.md` + the doc-FTS spike) and the v3
> plugin-framework conventions (`PLUGIN_FRAMEWORK_DEV_PLAN.md`). Companion: `SEARCH-FTS5-PLUGIN-HANDOFF.md`
> (background + evidence). Task format mirrors Lane's plan: **Goal / Files / Change / Tests / Done-when**.
> (Note: the repo's `project-plan.md` is occupied by Lane's multi-tenant plan — this search plan lives here.)

## Locked decisions (follow Lane — do not relitigate)

1. **Lexical FTS5 is the base.** BM25 + snippet + highlight + `porter unicode61 remove_diacritics 2`,
   zero AI cost. AI/vector, analytics, experiments are **separate future add-on plugins** (out of scope).
2. **Indexing rides the document write-time projection** (spike Q6) — a **core seam** in
   `DocumentProjection`, NOT route hooks (hooks only fire from `api-content-crud.ts`; admin + media
   writes would be missed). This is the accepted "small core touch"; it is not a removable plugin.
3. **Serving + engine + config = a `definePlugin` plugin** (`/api/search`, the FTS5 query engine, the
   Unicode sanitizer, KV cache, admin config UI). Removable; degrades to "no search UI" cleanly.
4. **One index, `documents_fts`**, keyed by `document_id`; content + media unified (media = a
   `document_type`). Mirrors the spike's measured-parity schema.
5. Conform to document-model rules R1–R12 (raw `prepare/bind/batch`; virtual tables in raw migrations;
   tenant-scoped; real-DB tests; E2E numbered 68+; regen bundle after migration edits).

---

## Pre-verification findings (2026-06-19, read-only)

Two riskiest assumptions checked against the repo before building:

- **Retry/resilience — SOFTENED (design win).** No `retryTransientD1` or transient-D1 retry exists; all
  six `DocumentsService.batch()` calls are raw. But because we index in the *same batch* as the doc
  write, the infowall #871 "FTS silently drops while the doc persists" class is structurally impossible
  here (atomic commit). The wrapper becomes optional whole-batch resilience, not a prereq. See T0.2.
- **`queryableFields` → FTS slots — PARTIAL (Risk-2 gap real).** `title`/`slug` are first-class document
  columns (free). But there is no full-text *body* mechanism: `QueryableField.kind` is scalar/facet/
  reference only, the `text` scalars are short `q_*` metadata, `extractPath` is top-level only, and no
  server-side rich-text→plaintext extraction exists. Added as **T0.1b**.

---

## Phase 0 — Core: schema + projection seam (the indexing base)

### T0.1 — `documents_fts` virtual table migration `[S]`
- **Goal:** the one FTS5 index, schema-matched to the spike for relevance parity.
- **Files:** `packages/core/migrations/0003_documents_fts.sql` (next free number); regen
  `src/db/migrations-bundle.ts`; re-sync `my-sonicjs-app/migrations/` (byte-identical) — **R9**.
- **Change:**
  ```sql
  CREATE VIRTUAL TABLE documents_fts USING fts5(
    title, slug, body,                                  -- indexed cols 0,1,2
    document_id UNINDEXED, root_id UNINDEXED, type_id UNINDEXED,
    tenant_id UNINDEXED, status UNINDEXED, is_published UNINDEXED,
    created_at UNINDEXED, updated_at UNINDEXED,
    tokenize='porter unicode61 remove_diacritics 2'
  );
  ```
  (Column layout/tokenizer must match the spike so the bm25 weight vector maps 1:1.) Virtual table lives
  **only** in the raw migration — **R2** (never in `db/schema.ts`).
- **Tests:** real-DB sqlite test asserts table creates + accepts insert/MATCH (**R10**).
- **Done when:** migration applies; bundle regenerated + committed; `my-sonicjs-app` copy byte-identical.

### T0.1b — Searchable-field declaration + plain-text extraction `[M]` (NEW — from pre-verify)
- **Goal:** declare which per-type `data` field feeds the FTS `body` slot, and extract its plain text.
- **Why (pre-verified):** `QueryableField.kind` is only `scalar|facet|reference`; the `type:'text'`
  scalars are short metadata bound to `q_*` columns (difficulty/author/mimeType/status…) — none are a
  full-text body. `extractPath` is top-level-key only, and there is **no** server-side
  rich-text→plaintext extraction (Quill/TinyMCE Delta is client-side only). `title`/`slug` are fine
  (first-class document columns).
- **Files:** `schemas/document.ts` (`QueryableField`), `services/document-projection.ts`,
  `services/document-types-seed.ts` (+ collection registration for user types).
- **Change:** add `kind:'fulltext'` (or a `fullText` flag) so a type declares its body field(s); add a
  small richtext/Delta/HTML→plaintext extractor; add nested-path support to `extractPath` if a body
  field is nested.
- **Tests:** Delta/HTML body → plaintext indexed + searchable; a type with no fulltext field still
  indexes title/slug.
- **Done when:** the body slot is declaratively selectable per type and rich text is searchable.

### T0.2 — FTS projection in `DocumentProjection` (the seam) `[M]`
- **Goal:** every document write also (de)indexes `documents_fts`, atomically, with universal coverage.
- **Files:** `packages/core/src/services/document-projection.ts`,
  `packages/core/src/services/documents.ts`.
- **Change:**
  - Add `buildFtsInsertStatements(doc, queryableFields, now)` + `buildFtsDeleteStatements(id)` returning
    D1 prepared statements (same shape as the existing facet/reference builders).
  - Map to FTS slots: `title`/`slug` from the document columns (`doc.title`/`doc.slug` — first-class,
    no declaration needed); `body` from the `kind:'fulltext'` field(s) added in **T0.1b** (with
    plain-text extraction). Scalars stay `q_*` columns — they are NOT full-text.
  - Fold the new statements into the **same batches** already assembled in `DocumentsService.create`
    (L145), `saveDraft` (L211/239), `publish` (L306/343/353/368), `unpublish` (L397), `erase` (L433) —
    next to `buildDerived*`. Mirror row-selection `(is_current_draft=1 OR is_published=1)` so the index
    matches facet coverage. **R1** (raw batch), **R3** (tenant-scoped), **R5** (count binds by hand).
  - Resilience (**pre-verified 2026-06-19**): no `retryTransientD1` exists here and
    `DocumentsService.batch()` is raw. But folding FTS into the *same* batch as the doc write makes the
    infowall #871 silent-drop class **structurally impossible** (FTS+doc+facets commit atomically — they
    cannot diverge). A retry wrapper is now **optional** whole-batch resilience, not a correctness
    prereq; if added it wraps the existing batch (helps facets/refs too) — separate from FTS.
- **Tests:** real-DB sqlite (**R10**): create→row searchable; saveDraft supersede→old text gone, new
  present; publish/unpublish→visibility column correct; erase→row removed; multi-field bm25 ordering.
- **Done when:** all four write paths index/deindex atomically; admin-created + media docs are searchable.

### T0.3 — Backfill / self-heal existing documents `[S]`
- **Goal:** populate `documents_fts` for docs written before the seam existed.
- **Files:** bootstrap (`middleware/bootstrap.ts`) self-heal, or a `scripts/backfill-fts.ts`.
- **Change:** idempotent pass that indexes current-draft/published rows missing from `documents_fts`
  (pattern: like `MigrationService.ensureDocumentGeneratedColumns` self-heal). Batched, retry-wrapped.
- **Tests:** seed docs pre-index → run backfill → all searchable; re-run is a no-op.

---

## Phase 1 — Plugin: lexical engine + serving + config

### T1.1 — Port the FTS5 query engine `[M]`
- **Goal:** BM25 search over `documents_fts` with snippet/highlight + Unicode-safe query sanitizing.
- **Files (new):** `packages/core/src/plugins/.../fts5-search-plugin/services/fts5-engine.ts`,
  `.../services/fts5-sanitize.ts`.
- **Change:** port infowall `fts5.service.ts` re-pointed (`content_fts`→`documents_fts`,
  `content_id`→`document_id`, `collection_id`→`type_id`) + `fts5-sanitize.ts` verbatim (CJK/Cyrillic
  safe, fold Latin diacritics). bm25 field boosts (title/slug/body), `snippet()`, `highlight()`.
  Visibility/tenancy filters native (`is_published`, `tenant_id`) per spike Q7.
- **Tests:** sqlite parity-style: stemming (`run`→running), diacritics (`cafe`→café), field-boost order,
  prefix match. **R10**.

### T1.2 — `definePlugin` search plugin + `/api/search` `[M]`
- **Goal:** the removable serving surface.
- **Files (new):** `.../fts5-search-plugin/index.ts`, `.../routes/api.ts`, `.../services/search-cache.ts`.
- **Change:** `definePlugin({ id:'fts5-search', ... })` — `register(app)` mounts `/api/search`
  (+ `/api/search/suggest`); KV result cache on `CACHE_KV` (port `search-cache.service.ts`, key by
  normalized query+filters, invalidate on settings change). No content-hook subscription (indexing is
  core). Public route uses `[{type:'public',id:'*'}]`, filters `is_published=1` (no published-only fast
  path — D5). Escape rendered output — **R8**.
- **Tests:** integration route test: query returns ranked hits; cache hit path; published-only filtering.

### T1.3 — Admin config UI + settings.service `[M]`
- **Goal:** lexical settings (bm25 weights, results limit, cache TTL, which types searchable).
- **Files (new):** `.../fts5-search-plugin/services/settings.service.ts`, `.../routes/admin.ts`;
  declarative `menu` + `configSchema` on the plugin.
- **Change:** mirror `email-plugin/services/settings.service.ts` for persistence (no `plugins` table).
  Catalyst admin page for config.
- **Tests:** settings round-trip; weight change reflected in ranking; cache invalidated on save.

---

## Phase 2 — Validation

### T2.1 — E2E + relevance sanity `[M]`
- **Files:** `tests/e2e/68-fts5-search.spec.ts` (next free ≥68 — **R11**).
- **Change:** Playwright: create content via admin → it becomes searchable; query UI returns ranked
  results w/ highlights; media + content in one result set; draft excluded from public search.
- **Optional:** a small BEIR-style relevance check (the spike's neutrality gate) if datasets are handy.
- **Done when:** E2E green; `npm test` + `tsc` + lint clean.

---

## Out of scope (future add-on plugins — keep separable)
- **AI Search plugin** — Vectorize + Workers AI, hybrid RRF; degrades to the lexical floor. Needs
  `AI`/`VECTORIZE` bindings (not configured here).
- **Analytics plugin** — search history/clicks/trending via a non-blocking event subscriber.
- **Experiments / Query-Enhancement plugins** — around-search wrap.
These compose the lexical base; do not bundle them into it (Lane's load-bearing rule).

## Sequencing
Phase 0 (T0.1→T0.2→T0.3, serial) is the foundation. Phase 1 fans out after T0.1 (engine can build
against the schema before the seam lands). Phase 2 last. Each task keeps the core suite + tsc + lint
green (**R10** real-DB coverage is mandatory — mock tests prove nothing about SQL).

## Review
_(to fill in as phases land.)_
