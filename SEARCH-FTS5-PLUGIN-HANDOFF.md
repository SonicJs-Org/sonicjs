# Handoff — Infowall FTS5 search → SonicJS (sonicjs-org) plugin

**Status:** review/planning only. No code written. Parked in git worktree
`worktree-search-fts5-plugin` (`.claude/worktrees/search-fts5-plugin`, branched off `origin/main`).
**Goal:** bring Infowall's lexical **FTS5 search** into sonicjs-org as a **plugin**, on the v3
document model.

---

## 0. Session tooling — launch with Grep/Glob (read first)

This Claude Code build (`2.1.181`) ships `Grep`/`Glob` as **opt-in** built-in tools. They are **NOT**
in the default tool set, and `--tools` is **exclusive** (no "default + extras" form):

- `--tools default` → everything **except** Grep/Glob.
- `--tools default,Grep,Glob` → **only** Glob+Grep (`default` is dropped — footgun).
- To get the full set **plus** Grep/Glob you must enumerate every built-in tool. Current full list:

```
claude --tools "Agent,AskUserQuestion,Bash,Edit,Read,ScheduleWakeup,Skill,ToolSearch,Workflow,Write,CronCreate,CronDelete,CronList,DesignSync,EnterPlanMode,EnterWorktree,ExitPlanMode,ExitWorktree,Monitor,NotebookEdit,PushNotification,RemoteTrigger,TaskCreate,TaskGet,TaskList,TaskOutput,TaskStop,TaskUpdate,WebFetch,WebSearch,Grep,Glob"
```

⚠️ Brittle: if a Claude Code update adds a new built-in tool, this static list silently omits it.
**`grep`/`rg` via the Bash tool fully cover the dedicated `Grep` tool** — using the binary is the
zero-maintenance path. Only enumerate if you specifically want the dedicated tools.

---

## 1. The big idea (from `INFOWALL-SEARCH-FOR-SONICJS-PLUGIN.md`)

Two-tier search: a **lean, always-on, zero-AI-cost FTS5 lexical engine** (BM25, snippet, highlight,
`porter unicode61 remove_diacritics 2`, synonyms, ranking pipeline, facets) + **opt-in plugins** for
anything with infra cost (AI/vector, analytics, experiments). **Load-bearing rule:** keep the lexical
engine free of AI cost; the AI/vector half is a *separate* plugin that degrades to the FTS5 floor when
absent. Do **not** bundle them.

## 2. Verified findings — sonicjs-org is NOT a copy-paste target

The two codebases (both SonicJS-derived) have diverged at the data-model level. Confirmed by review +
grep in this repo:

| Concern | infowall (source) | sonicjs-org (target) | Verdict |
|---|---|---|---|
| Content storage | per-collection `c_*` tables → `content_c_*_fts` | **one `documents` table** (JSON `data`, `q_*` virtual cols) | one `documents_fts`, not N |
| Existing search | mature (15 tables, AI/vector) | **NONE** — greenfield (no `content_fts`, no `MATCH`) | build fresh |
| Plugin SDK | `definePlugin` + search seams | `definePlugin` w/ `register/onBoot/hooks/menu/configSchema/crons/lifecycle/capabilities` | see gap below |
| **Search seams** (mode registry, `search:performed` event, around-search wrap, `adminTabs`) | present in infowall | **ABSENT here** (grep-confirmed) | would be net-new SDK work |
| `queryable_fields` (declarative per-type fields) | yes | **YES — present** (doc routes/schemas) | maps 1:1 ✅ |
| FTS5 mechanics (sanitizer, bm25 boosts, snippet/highlight) | `search/services/fts5*.ts` | n/a | ports cleanly ✅ |
| KV result cache | `search-cache.service.ts` on `CACHE_KV` | `CACHE_KV` exists | ports ✅ |
| AI / Vectorize bindings | yes | **NO** (`my-sonicjs-app/wrangler.toml` has DB, CACHE_KV, MEDIA_BUCKET only) | AI plugin out of scope ✅ |

**Two reframings vs the infowall handoff:**
1. **Greenfield-for-search.** All of the infowall §4/spike-Q8 *convergence* (dual-write → backfill →
   read-flip → drop) is **moot** — there's nothing to migrate from. We build `documents_fts` as the one
   and only index from day one. The handoff's "v3 future" is simply "what we do."
2. **The seams it leans on don't exist here.** The mode registry ("a search engine as a plugin"), the
   event seam, the around-search wrap, and `adminTabs` are infowall constructs, not in sonicjs-org's
   SDK. With only a lexical engine and **no AI bindings**, the mode registry is optional scaffolding —
   a lexical-only MVP can mount `/api/search` directly against `documents_fts` and add the registry
   later iff an AI plugin ever arrives.

## 3. The `documents_fts` projection (the engine seam for v3)

From the **measured** spike (`plans/search/decomposition/SPIKE-FINDINGS-DOCUMENT-FTS-PROJECTION-v1.md`,
12/12 green, BM25/snippet/highlight byte-identical to 10 decimals):

- `documents_fts` FTS5 virtual table keyed by `document_id`; the full-text analog of `document_facets`.
- **Parity keys:** tokenizer `porter unicode61 remove_diacritics 2` + 10-column layout
  (`title, slug, body` indexed at cols 0/1/2; metadata `UNINDEXED`) so the existing
  `bm25(…, w0..w9)` weight vector maps 1:1.
- Content + media collapse into one index (media = another `document_type`).
- Which fields are indexed + per-field weights driven by the doc type's **`queryable_fields`** (present
  here).
- Visibility/tenancy native via `documents.is_published`/`tenant_id`/`document_permissions` on the
  projection — no JOIN.
- **Retry (pre-verified 2026-06-19, softened):** no `retryTransientD1` exists here; `DocumentsService`
  batches are raw. But indexing in the *same* batch as the doc write makes the #871 silent-drop class
  structurally impossible (atomic commit) — so the wrapper is optional resilience, not mandatory.

## 4. RESOLVED: index at the service/projection layer, not route hooks

Grep-verified in this worktree:
- The v3 plugin framework is **live here** — Phase 1/2 commits (`7ad63cca1`, `ce08884aa`) are in
  `origin/main`. Content lifecycle hooks (`content:after:create|update|delete|publish`) fire — but are
  dispatched **only from `routes/api-content-crud.ts`**.
- **Four** routes write via `DocumentsService` — `api-content-crud.ts`, `api.ts`, `admin-documents.ts`,
  `admin-content.ts` — and **only the first dispatches hooks**. `admin-content.ts` (the *primary* admin
  authoring route) and all media writes dispatch **nothing**.
- `DocumentsService` dispatches no hooks; it is where `document_facets`/`document_references` project
  (the universal write chokepoint — facet block near `documents.ts:433`; projection logic in
  `services/document-projection.ts`).

**Therefore:** a hook-driven FTS index would silently miss all admin-created content + media —
unacceptable for search. The index MUST ride the **`DocumentsService` projection** (spike Q6), the one
path every write funnels through. Carry the `retryTransientD1` wrapper there (🔴 §3).

**Consequence — the real decision:** the *indexing* half can't be a 100%-removable pure plugin; it
needs a **projection seam in core** (or a small core touch) at the service layer. The *serving* half
(`/api/search`, query, `fts5-sanitize`, KV cache, admin UI) IS a clean `definePlugin` plugin. **Decided
(from code + the framework's existing direction; see v2):** fold FTS index writes directly into the
`DocumentsService` write batch alongside facets — including the `updateInPlace` default-edit path — no
new registration seam for the lexical base. The mode-registry seam is YAGNI here: the existing
`ai-search-plugin` uses a hardcoded `keyword|ai` if/else with AI dormant, so FTS5 becomes the `keyword`
backend; a registry is revisited only when `AI`/`VECTORIZE_INDEX` bindings land (revisit trigger is
self-evident from code).

## 5. Open questions — RESOLVED in v2 (`SEARCH-FTS5-PLUGIN-PLAN-v2.md`)

1. **Settings persistence — DECIDED.** The `plugins` table is in `db/schema.ts` but **no raw migration
   creates it** → empty on greenfield. Persist via KV (`CACHE_KV`) or a `plugin_settings` document type
   (v2). Infowall's `plugins.settings` pattern does not apply here.
2. **Searchable-text extraction — DECIDED.** `title`/`slug` are document columns (free); no server-side
   rich-text→plaintext exists → add a `kind:'fulltext'` `queryableFields` entry + a recursive plaintext
   harvester (v2 T0.1b/T0.3).
3. **Index target — DECIDED.** Index current-draft + published; keep visibility filtering JOIN-free by
   **deindexing soft-deleted / `visible=0` rows at write time** (JOIN to `documents` only as fallback).

## 6. Status

Planning COMPLETE. The authoritative plan is **`SEARCH-FTS5-PLUGIN-PLAN-v2.md`** (post deep code review,
2026-06-19) — it carries the reality-check ledger (L1–L27, file:line evidence) and the Lane-alignment
ledger (LA0–LA6). Every fork above is decided there from code + written direction. **Building is on hold
pending the user's go-ahead** (no code written). E2E coverage lands at `tests/e2e/82-fts5-search.spec.ts`
(next free is 82, not 68) at implementation time.

## 7. Reference map

**sonicjs-org (this repo):**
- Plugin SDK: `packages/core/src/plugins/sdk/define-plugin.ts`
- Hook catalog: `packages/core/src/plugins/hooks/catalog.ts` (`content:after:create|update|delete|publish`)
- Plugin template: `packages/core/src/plugins/core-plugins/email-plugin/index.ts`
- Write path / facet projection: `packages/core/src/services/documents.ts`
- Read chokepoint: `packages/core/src/services/document-repository.ts`
- Migrations: `packages/core/migrations/0002_documents.sql` (next free `0003`); self-heal
  `packages/core/src/services/migrations.ts`
- Bindings: `my-sonicjs-app/wrangler.toml`
- Existing plan in worktree: `PLUGIN_FRAMEWORK_DEV_PLAN.md`

**infowall (source, read-only ref — `/home/siddhartha/Infowall/infowall-ai/infowall`):**
- Engine: `packages/core/src/search/services/fts5.service.ts`, `fts5-sanitize.ts`,
  `search-cache.service.ts`, `ai-search.ts` (orchestrator/mode registry)
- FTS5 schema: `packages/core/migrations/020_fts5_search.sql`, `101_fts5_denormalize.sql`,
  `064_media_fts5.sql`
- Design handoff: `INFOWALL-SEARCH-FOR-SONICJS-PLUGIN.md`
- Plugin→core audit: `INFOWALL-SEARCH-PLUGIN-TO-CORE-AUDIT.md`
- Doc-FTS spike: `plans/search/decomposition/SPIKE-FINDINGS-DOCUMENT-FTS-PROJECTION-v1.md`

**Do NOT read** (token traps): `INFOWALL-SEARCH-FEATURE-FOR-DRUPAL-PORT.md` (710KB),
`packages/core/src/db/migrations-bundle.ts`, `dist/**`.
