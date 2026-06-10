# SonicJS AI Development Guidelines

Cloudflare-native headless CMS built with **Hono.js** + TypeScript on **Cloudflare Workers** / **D1**.

## Core Technology Stack
- **Framework**: Hono.js
- **Runtime**: Cloudflare Workers
- **Database**: Cloudflare D1 (SQLite) with Drizzle ORM (legacy only — document layer is raw SQL)
- **Validation**: Zod
- **Testing**: Vitest (unit + real-SQLite) + Playwright (E2E)
- **Frontend**: HTMX + HTML tagged templates (admin UI)
- **Auth**: Better Auth (session + RBAC) — `c.get('user') === { userId, email, role }`
- **Deployment**: Wrangler

## Workspace boundary (Conductor)

- Work in `.conductor/hong-kong-v3/`. **Never read or write** `/Users/lane/Dev/refs/sonicjs/` (sibling main checkout).
- Target branch: `origin/v3`. PRs: `gh pr create --base v3`. Diff: `git diff origin/v3...`.

## Architecture direction: Document Model (authoritative)

The project is migrating from per-feature tables (`content`, `media`, `testimonials`, `email_log`, …) to a unified **document repository**. **All new features build on the document model. Do not add new feature tables.**

Full design + remediation runbook: `docs/ai/plans/document-model-poc-plan.md` (Appendix A = original design; §1–§7 = current implementation status, defect IDs `D1`–`D48`).

### The 5 document tables (migration `0002_documents.sql`)
1. **`document_types`** — registered schemas (code/plugin-owned).
2. **`documents`** — every content/media/plugin record + every historical version. Queryable scalar fields are exposed as **indexed JSON `VIRTUAL` generated columns** (`q_*`) on this table — `json_extract(data, '$.path')`.
3. **`document_references`** — typed strong/weak edges (FK to `documents`); powers "where used" and reference-aware delete.
4. **`document_facets`** — indexed rows for multi-valued scalar fields (e.g. `tags`) — the one case generated columns can't cover.
5. **`document_permissions`** — per-document ACL overrides on top of type-level base grants.

### Implementation rules (non-negotiable — each line is a bug already shipped)

| # | Rule |
|---|------|
| **R1** | All document writes use raw `env.DB.prepare(sql).bind(...)` inside `env.DB.batch([...])`. **Never** put Drizzle query-builder objects (`db.update()`, `db.insert()`) into a `batch`. |
| **R2** | `VIRTUAL` generated columns and partial / expression UNIQUE indexes live **only** in raw migrations (`0002`, `0003`, and future ALTERs via `MigrationService.ensureDocumentGeneratedColumns`). Never declare them in `db/schema.ts` (Drizzle can't express them). |
| **R3** | Every document read/write is tenant-scoped. Go through `DocumentRepository` (injects `this.tenantId`) or include `AND tenant_id = ?`. POC tenant = literal `'default'`. |
| **R4** | Document route handlers must not build raw document SQL. Use `DocumentRepository.list()` / `DocumentsService`. (Legacy `content`/`media` routes are the exception — and are being decommissioned.) |
| **R5** | Count placeholders/columns/binds by hand before committing any `INSERT`. Mock tests can't catch arithmetic bugs (R10). |
| **R6** | `version_number` is derived in SQL: `(SELECT COALESCE(MAX(version_number),0)+1 FROM documents WHERE root_id = ?)`. Never compute in JS — the partial unique index `idx_documents_unique_version` will reject concurrent collisions. |
| **R7** | Derived rows (`document_facets`, `document_references`) exist **only** for the current-draft and published rows of a root. Delete explicitly on supersede/unpublish — never rely on `ON DELETE CASCADE` (D1 FK enforcement is not guaranteed). |
| **R8** | Escape every user-controlled value rendered into HTML with `escapeHtml` from `utils/sanitize`. |
| **R9** | After editing any `packages/core/migrations/*.sql`: run `cd packages/core && npm run generate:migrations`, re-sync the `my-sonicjs-app/migrations/` copies (byte-identical), commit the regenerated `src/db/migrations-bundle.ts`. |
| **R10** | Unit tests on the pure-mock DB cannot verify SQL, constraints, batch atomicity, generated columns, or bind counts. Real coverage requires the `better-sqlite3` harness — `documents.sqlite.test.ts` + the `*.integration.test.ts` route harness. |
| **R11** | New E2E specs are numbered **68+** (highest existing is 67). |
| **R12** | POC runs **alongside** legacy paths. Do not drop legacy plugin tables in the POC — decommission only after read-flip + backfill + grep-gate (see plan §"Decommissioning"). |

### Key behaviors to preserve

- **Two axes**: `is_current_draft` and `is_published` are **separate** — a published doc stays live while an editor saves new drafts. `status` (`draft`/`published`/`archived`) is a derived UI label only.
- **Timestamps**: `documents.created_at`/`updated_at` are stored in **seconds** (legacy `content` used ms). Use `documentSecondsToMs()` from `services/documents.ts` at every response/render boundary that expects ms.
- **Pagination**: keyset on `(updated_at, id)` for all JSON APIs. `OFFSET` only allowed in admin HTML page-number tables, and only with an explicit comment.
- **ACL**: `isAllowed` precedence = **deny wins → explicit allow → base grants**. Authed callers' `principalSet` must include `{ type: 'role', id: <role> }` (base grants only match `public` + `role`).
- **Generated-column budget**: D1 hard limit is 100 columns/table. Adding `q_*` columns goes through `MigrationService.ensureDocumentGeneratedColumns()` (idempotent `table_xinfo` + ALTER) — **not** a new migration file (D45 pattern).
- **PII / right-to-erasure**: types with PII set `settings.pii = true` and **hard-erase** all versions (facets → refs → permissions → all `documents` rows in one batch) + delete R2 object.

### Every collection is doc-backed (global)

`autoRegisterCollectionDocumentTypes(db)` runs at bootstrap (after collection sync) and registers a document type (id == collection name) for **every active user collection**. All `/admin/content` writes go to `documents`. `collections` is the **permanent** schema/type registry — do not target it for deletion.

### Bootstrap order

```
migrations (0001 core, 0002 documents, 0003 platform)
→ MigrationService.ensureDocumentGeneratedColumns (q_* self-heal)
→ collection sync
→ autoRegisterCollectionDocumentTypes
→ bootstrapDocumentTypes (seed system types)
→ plugin onBoot
```

Entry point: `packages/core/src/middleware/bootstrap.ts`.

### Auth principals (Better Auth)

```ts
c.get('user') // { userId, email, role }

// Authed routes:
const principalSet = [
  { type: 'user', id: user.userId },
  { type: 'role', id: user.role },
]

// Public routes:
const principalSet = [{ type: 'public', id: '*' }]
```

Base grants only match `public` + `role`, so the `role` principal is mandatory for authed callers (R11 rule in plan). Tenant constant POC-wide: literal `'default'`.

### Drizzle vs raw SQL split

- `db/schema.ts` = legacy tables only (no `documents*`, no `q_*`, no partial unique indexes). R2.
- All document SQL lives in raw migrations (`0002`, `0003`, future) + `DocumentsService` / `DocumentRepository`.

### Migration numbering

- `0001_core.sql` — Better Auth tables.
- `0002_documents.sql` — document repository (5 tables + `q_*` generated cols + partial unique indexes).
- `0003_platform.sql` — platform tables (collections, settings, plugins, etc.).
- **Next free: `0004_*`.**
- Adding queryable scalar fields: use `MigrationService.ensureDocumentGeneratedColumns()` self-heal — **not** a new migration file (D45 pattern).

### Files (cheat-sheet)

| Concern | File |
|---|---|
| Schema | `packages/core/migrations/0002_documents.sql`, `0003_platform.sql` |
| Self-heal `q_*` columns | `packages/core/src/services/migrations.ts` (`ensureDocumentGeneratedColumns`) |
| Bootstrap | `packages/core/src/middleware/bootstrap.ts` |
| Write API | `packages/core/src/services/documents.ts` (`create`, `saveDraft`, `publish`, `unpublish`, `erase`) |
| Read chokepoint | `packages/core/src/services/document-repository.ts` (`list`, `listPublished`, `listDrafts`, `isAllowed`) |
| Projection | `packages/core/src/services/document-projection.ts` |
| ACL resolver | `packages/core/src/services/document-permissions.ts` |
| Type registry | `packages/core/src/services/document-type-registry.ts`, `document-types-seed.ts` |
| Public API | `packages/core/src/routes/api.ts`, `api-content-crud.ts`, `api-documents.ts` |
| Admin routes | `packages/core/src/routes/admin-content.ts` (primary), `admin-documents.ts` |
| Media adapter | `packages/core/src/services/media-documents.ts` |
| Real-DB tests | `__tests__/services/documents.sqlite.test.ts`, `__tests__/**/*.integration.test.ts` |
| D1 test adapter | `packages/core/src/__tests__/utils/d1-sqlite.ts` (better-sqlite3 → D1 shim) |

### Do not Read (token traps)

- `packages/core/src/db/migrations-bundle.ts` — generated, ~33KB.
- `packages/core/dist/**` — build output.
- `my-sonicjs-app/migrations/*.sql` — byte-identical copies of `packages/core/migrations/`. Read the originals.
- `docs/ai/claude-memory.json` — MCP memory store.
- `node_modules/**`, `.wrangler/**`, `playwright-report/**`, `test-results/**`.

### Adding a new feature → checklist

1. **Register a document type** in your plugin's `onBoot` (don't add a table). Source = `'system'` for plugin-owned, `'user'` for collection-driven.
2. **Add queryable fields** as `q_*` entries in `ensureDocumentGeneratedColumns` (no new migration file). Stay under the 100-column budget.
3. **Writes**: go through `DocumentsService` (which uses raw `prepare/bind/batch` — R1) — tenant defaults to `'default'`.
4. **Reads**: go through `DocumentRepository.list()` (R4) — never inline `prepare` in a handler.
5. **Public exposure**: set `settings.baseGrants.public = ['read']` only if the data is non-PII.
6. **PII**: set `settings.pii = true` and ensure the erase path covers it.
7. **Tests**: add at least one `*.sqlite.test.ts` or `*.integration.test.ts` case. Mock tests prove nothing about SQL (R10).
8. **E2E**: add a Playwright spec (numbered 68+).

### Status snapshot (avoid re-investigating)

- **Auto `content`→`documents` backfill**: descoped (new installs only). Manual `scripts/backfill-content.ts` preserves `created_at` if ever needed.
- **Media library read-flip**: in progress, slice 3 (`MediaDocumentService.list()` done; admin handlers + `api-media` DELETE still on legacy `media`).
- **Workflow plugin**: routes commented out, dead code; not on critical path for `content` DROP.
- **`content`/`media` table DROP**: blocked (D34/D35 + media read-flip pending). `collections` table is permanent.

## Token-Efficient Tooling (REQUIRED before grep/Read sprees)

Repo indexed by **codegraph**. Bash auto-proxied by **rtk**. Default reply mode **caveman**.

- **Code lookup**: call `mcp__codegraph__codegraph_explore` FIRST for any "how does X work / trace flow / where is X used" question. ONE call returns verbatim source grouped by file — replaces 5–20 Grep/Read calls.
- **Symbol location only**: `codegraph_search`.
- **Call graph / impact**: `codegraph_callers`, `codegraph_callees`, `codegraph_impact`.
- **Bash**: hook rewrites to `rtk <cmd>` automatically. `rtk gain` audits savings.
- **Replies**: caveman mode (full) — drop articles/filler. Code/commits/security warnings stay normal. Toggle `/caveman` or "stop caveman".
- **Subagent delegation** (compressed output, ~60% smaller results): `cavecrew-investigator` (locate), `cavecrew-builder` (1–2 file edit), `cavecrew-reviewer` (diff review).

Anti-patterns: `grep -r` across repo when codegraph answers; reading 5+ files to learn a flow; spawning a subagent for a known file; verbose narration.

## E2E Testing is Mandatory

Every feature/fix ships with a Playwright spec in `tests/e2e/`. Workflow:

1. Implement
2. Add `tests/e2e/<NN>-<slug>.spec.ts` (NN = next sequential; current floor 68 — R11)
3. `npx playwright test tests/e2e/<NN>-<slug>.spec.ts` (add `--headed` to debug)
4. Fix any failures
5. Commit implementation + tests together

Spec skeleton:

```typescript
import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Feature Name', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('does the thing', async ({ page }) => {
    // …
  })
})
```

Cover: user interactions, data persistence, UI state, error/validation paths, integration points.

## Verification commands

```bash
# Type safety (core)
cd packages/core && npm run type-check

# Unit + real-DB tests (root → @sonicjs-cms/core)
npm test
npm test -- <pattern>            # single test by name/path

# E2E (root)
npm run e2e
npx playwright test tests/e2e/68-x.spec.ts            # one spec
npx playwright test tests/e2e/68-x.spec.ts --headed   # debug

# Local D1 — reset + migrate + seed
cd my-sonicjs-app && npm run setup:db

# Dev server (wrangler :8787)
cd my-sonicjs-app && npm run dev

# Migration bundle regen (after any packages/core/migrations/*.sql edit)
cd packages/core && npm run generate:migrations
```

After **any** `packages/core/migrations/*.sql` change: regenerate the bundle, re-sync `my-sonicjs-app/migrations/`, commit the regenerated `migrations-bundle.ts` (R9).

D1's **100 bound params/statement** and **100 columns/table** limits do not reproduce on local SQLite — cover with logic unit tests (chunk counts, column budget).

## Development Workflow

1. **Plan first** — read the codebase (use `codegraph_explore`), write a plan to `project-plan.md`.
2. **Todo management** — discrete checkable items.
3. **Get approval** before starting non-trivial work.
4. **Iterative** — mark items done as you go.
5. **High-level updates** — terse explanations per step.
6. **Minimal changes** — no scope creep, no premature abstractions.
7. **Review section** in `project-plan.md` summarizing what shipped.

## Key Principles

- **Edge-first** (Cloudflare global edge).
- **TypeScript-first**.
- **Configuration over UI** (developer-centric).
- **AI-friendly** (clean structure, codegraph-indexed).
- **Document model is the data model** — new tables need an explicit reason in the design plan.

## Admin UI

Glass-morphism / catalyst design system. Reference patterns before building new pages:

- Pages: `packages/core/src/templates/pages/admin-*.template.ts`
- Layout: `packages/core/src/templates/layouts/admin-layout-v2.template.ts` (legacy), catalyst layout for new work
- Components: `packages/core/src/templates/components/`
- Routes: `packages/core/src/routes/admin.ts`, `admin-content.ts`

Use `codegraph_explore` to inspect current patterns before building new pages.

## Security

- Never expose secrets in code or tests.
- Validate all user input at the boundary (Zod).
- Escape all user-controlled HTML output (R8 — `escapeHtml` from `utils/sanitize`).
- ACL gates every document mutation in admin routes (Phase 2b — `denyIfNotAllowed` helper).
- Public API enforces `isAllowed` with `[{type:'public',id:'*'}]` — no `is_published`-only fast paths (D5).
- Tenant scope (`tenant_id`) on every doc query (R3).

## Claude AI Memory Setup

Project uses Claude's memory MCP server for shared cross-session context.

1. `cp .claude/settings.shared.json .claude/settings.local.json`
2. `npm install -g @modelcontextprotocol/server-memory`
3. Restart Claude Desktop

Storage: `docs/ai/claude-memory.json` (tracked in git).
