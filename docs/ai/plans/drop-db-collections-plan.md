# Drop DB-Defined Collections — Dev Plan

## Goal

Remove DB-defined collection support. Collections become code-only (Payload-style), registered via `registerCollections()` in app boot. Eliminate the dual-source-of-truth problem (DB rows vs code config drifting across envs).

## Outcome

- `collections` table dropped from schema.
- Admin UI for creating/editing collections deleted.
- Admin API CRUD for collections (`POST/PATCH/DELETE /admin/api/collections`) deleted.
- All consumers (`SELECT * FROM collections`) refactored to read from an in-memory `CollectionRegistry` populated by `loadCollectionConfigs()`.
- `autoRegisterCollectionDocumentTypes` reads from registry instead of `collections` table.
- E2E + unit tests covering DB path deleted; replaced by code-config tests.

## Non-Goals

- Form.io shadow collections — out of scope (separate decision; this plan removes the sync wiring as side effect since it targeted `collections` table).
- Migrating existing user installs — POC stage, no install base. Add a one-shot CLI export in follow-up if needed.
- Changing the `documents` model or `document_types` registry.

---

## Phase 1 — Build Code-Config Registry (foundation)

**Goal**: Single in-memory source for all collection reads, populated at bootstrap from code.

### 1.1 Create `CollectionRegistry` service

- File: `packages/core/src/services/collection-registry.ts` (new)
- Shape:
  ```ts
  class CollectionRegistry {
    private byName = new Map<string, CollectionConfig>()
    register(configs: CollectionConfig[]): void
    list(): CollectionConfig[]
    getByName(name: string): CollectionConfig | undefined
    getById(id: string): CollectionConfig | undefined  // id == name for code-defined
    isActive(name: string): boolean
  }
  ```
- Stable IDs: code-defined collection `id` = collection `name` (no random UUIDs — they break across envs and were the original DB-pattern bug).
- Export singleton or attach to `c.env` / Hono context.

### 1.2 Wire registry into bootstrap

- File: `packages/core/src/middleware/bootstrap.ts:115`
- Replace `syncCollections(c.env.DB)` call with `registry.register(await loadCollectionConfigs())`.
- Keep `loadCollectionConfigs()` in `collection-loader.ts` — already does code discovery.

### 1.3 Update `autoRegisterCollectionDocumentTypes`

- File: `packages/core/src/services/document-types-seed.ts:107` (currently stub returning `[]`)
- Read from registry, not DB. For each active collection, register a `document_type` row (id == collection name).
- File: `packages/core/src/middleware/bootstrap.ts:147` — bootstrap order already correct (collection load → autoRegister → seed).

### 1.4 Unit tests

- `__tests__/services/collection-registry.test.ts` — register/list/getByName/dedup behavior.

---

## Phase 2 — Migrate Consumers Off `collections` Table

**Goal**: zero `SELECT … FROM collections` in the codebase.

### 2.1 Refactor public API readers

Replace raw SQL with registry calls:

| File | Lines | Change |
|---|---|---|
| `routes/api.ts` | 624, 675, 698, 808 | `SELECT * FROM collections` → `registry.list()` / `getByName()` |
| `routes/api-content-crud.ts` | 24, 111, 303 | `SELECT id, name FROM collections WHERE name=?` → `registry.getByName(name)` |
| `routes/api-system.ts` | 139 | counts: iterate `registry.list()` |
| `routes/admin-api.ts` | 31 | `COUNT(*)` → `registry.list().length` |

### 2.2 Refactor plugin readers

| Plugin | File | Change |
|---|---|---|
| ai-search | `plugins/core-plugins/ai-search-plugin/routes/admin.ts:46` | registry.list() |
| ai-search | `services/indexer.ts:31`, `services/ai-search.ts:108,183` | registry lookup |
| seed-data | `plugins/core-plugins/seed-data-plugin/services/seed-data-service.ts:144` | registry.list() |
| cache | `plugins/cache/services/cache-warming.ts:60` | registry.list() |
| workflow | `plugins/core-plugins/workflow-plugin/migrations.ts:122` | drop schema check (workflow plugin is dead code per CLAUDE.md anyway) |

### 2.3 Verify with grep gate

```bash
grep -r "FROM collections" packages/core/src
# Expected: 0 results outside of explicitly noted historical/test files.
```

### 2.4 Tests

- Update each touched route's integration test to seed the registry instead of inserting `collections` rows.
- Cover `api-content-crud` flow against registry-only path.

---

## Phase 3 — Delete Admin UI Path

### 3.1 Routes

Delete `packages/core/src/routes/admin-collections.ts` (all of `:107-450`):
- `GET /admin/collections` (list page)
- `GET /admin/collections/new`
- `POST /admin/collections`
- `GET /admin/collections/:id` (edit)
- `POST /admin/collections/:id` (update)

Remove route mount from `packages/core/src/routes/admin.ts` (find and delete the `app.route('/admin/collections', adminCollectionsRouter)` line).

### 3.2 Templates

Delete:
- `packages/core/src/templates/pages/admin-collections-list.template.ts`
- `packages/core/src/templates/pages/admin-collections-form.template.ts`

### 3.3 Admin nav

- Find sidebar/nav that links to `/admin/collections` (likely `admin-layout-v2.template.ts` and catalyst layout).
- Replace with **read-only** view: list code-defined collections (from registry), no create/edit buttons. Or remove the link entirely if not valuable.
- Decision point: keep a read-only `/admin/collections` page (recommended — useful for content editors to see what's available) or drop entirely.

### 3.4 Admin API CRUD

Delete from `packages/core/src/routes/admin-api.ts`:
- `POST /admin/api/collections` (429-528)
- `PATCH /admin/api/collections/:id` (531-601)
- `DELETE /admin/api/collections/:id` (604-641)

Keep `GET /admin/api/collections` — refactor to read from registry (useful for admin UI dropdowns when picking collection for content creation).

---

## Phase 4 — Drop Schema + Cleanup

### 4.1 Remove Drizzle schema

- File: `packages/core/src/db/schema.ts`
- Delete: `collections` table (`:87`), `insertCollectionSchema` (`:250`), `selectCollectionSchema` (`:255`), `Collection` / `NewCollection` types (`:402-403`).

### 4.2 Drop sync services

Delete:
- `packages/core/src/services/collection-sync.ts` (entire file)
- `packages/core/src/services/form-collection-sync.ts` (entire file — Form.io shadow collections)

Remove imports + calls in `bootstrap.ts`:
- Line `115`: `syncCollections(c.env.DB)` — already replaced in Phase 1.
- Line `124`: `syncAllFormCollections(c.env.DB)` — delete.

### 4.3 Migration: DROP TABLE collections

- New migration: `packages/core/migrations/0004_drop_collections.sql`
  ```sql
  DROP TABLE IF EXISTS collections;
  ```
- Run `cd packages/core && npm run generate:migrations` (R9).
- Re-sync `my-sonicjs-app/migrations/` byte-identically.
- Commit regenerated `src/db/migrations-bundle.ts`.

### 4.4 Public API exports

- File: `packages/core/src/index.ts:66`
- Keep `registerCollections` export — primary public API now.
- Remove any exports of sync helpers, `Collection`/`NewCollection` types, admin route mounts.

---

## Phase 5 — Test Cleanup

### 5.1 Delete obsolete tests

| Test | Reason |
|---|---|
| `tests/e2e/04-collections.spec.ts` | UI create/edit/delete — path gone |
| `tests/e2e/08-collections-api.spec.ts` | Admin API CRUD gone |
| `tests/e2e/08b-admin-collections-api.spec.ts` | Admin API CRUD gone |
| `tests/e2e/22-collection-field-edit.spec.ts` | UI field editing gone |
| `__tests__/routes/collections.api.test.ts` | Admin API CRUD gone |
| `__tests__/services/collections.integration.test.ts` | sync service gone |
| `__tests__/services/collections.crud.test.ts` | CRUD path gone |

### 5.2 Keep + update

| Test | Update |
|---|---|
| `tests/e2e/20-content-api-collection-filter.spec.ts` | Reseed via code-config registration in test setup |
| `__tests__/services/collections.schema.test.ts` | Repurpose to validate `CollectionConfig` Zod (collection-loader's validator) |
| `__tests__/services/collections.models.test.ts` | Keep if it tests `CollectionConfig` types; delete if it's DB-row tests |
| `__tests__/utils/collections.fixtures.ts` | Convert from DB-row fixtures → `CollectionConfig` fixtures |
| `__tests__/routes/admin-api-references.test.ts` | Update reference resolution to use registry |

### 5.3 New E2E (numbered 68+, per R11)

- `tests/e2e/68-code-defined-collections.spec.ts` — assert:
  - Code-registered collection appears in `GET /admin/api/collections`.
  - Content can be created against a code-defined collection (POST `/admin/api/content`).
  - Content filtering by collection name works.
  - No `POST /admin/api/collections` route exists (404).
  - No `/admin/collections/new` page exists (404).

---

## Phase 6 — Docs

### 6.1 Update CLAUDE.md

- Add to "Adding a new feature → checklist": collections are code-only; register via `registerCollections()` in app boot.
- Remove any reference to admin-UI collection creation.

### 6.2 Update getting-started docs

- `docs/` (find collection-creation guide via grep).
- Replace "create a collection in the admin UI" with code example:
  ```ts
  import { registerCollections } from '@sonicjs-cms/core'
  registerCollections([
    { name: 'blog_posts', label: 'Blog Posts', fields: [...] },
  ])
  ```

### 6.3 Migration note for existing users (if any)

- `docs/ai/plans/drop-db-collections-plan.md` (this file) — keep as historical record.
- `MIGRATION-v3.md` (or similar) — one-shot export CLI optional follow-up. POC stage = no users to migrate.

---

## Verification Checklist

```bash
# Type safety
cd packages/core && npm run type-check

# Unit + real-DB
npm test

# E2E
npm run e2e

# Grep gate — zero references to dropped table/services
grep -r "FROM collections" packages/core/src        # → 0
grep -r "syncCollections\|syncCollection\|collection-sync" packages/core/src  # → 0
grep -r "admin-collections-list\|admin-collections-form" packages/core/src    # → 0
grep -r "POST.*\/admin\/api\/collections" tests/    # → 0

# Migration bundle regenerated
cd packages/core && npm run generate:migrations
git diff src/db/migrations-bundle.ts  # → expected changes only

# Boot
cd my-sonicjs-app && npm run setup:db && npm run dev
# Hit /admin/content — should still list/create content backed by code-defined collections
```

---

## Risk + Rollback

| Risk | Mitigation |
|---|---|
| Plugin consumers (ai-search, seed-data, cache) break | Phase 2.2 refactors each before Phase 4 drops table. CI gate. |
| `document_types` registry loses collection-backed types | Phase 1.3 ensures `autoRegisterCollectionDocumentTypes` reads registry before doc-type seed runs. |
| Existing user DB has `collections` rows | POC stage — no users. Migration `0004` is destructive. Add data-export CLI only if requirements change. |
| Form.io shadow collections regression | Form.io plugin currently creates shadow rows. Phase 4.2 drops the sync — verify Form.io still functions without it (likely depends on `documents` table, not `collections`). Investigate in Phase 4. |
| `collections.id` referenced in foreign keys elsewhere | Check schema.ts for FKs pointing at `collections.id` — likely none (document model uses `type` string, not FK). Confirm in Phase 4.1. |

Rollback: revert Phase 4 commits (schema delete + migration). Phase 1-3 changes are forward-compatible — registry can coexist with DB reads if rollback needed mid-flight.

---

## Sequencing (suggested PR breakdown)

1. **PR 1 — Registry foundation** (Phase 1): add `CollectionRegistry`, populate at bootstrap, no consumer changes yet. Both code paths coexist.
2. **PR 2 — Consumer migration** (Phase 2): refactor all `FROM collections` to registry calls. Still no UI changes. Verify with grep gate.
3. **PR 3 — Delete admin UI + API** (Phase 3): remove create/edit/delete paths. Keep read-only `GET /admin/api/collections` (registry-backed). E2E updates.
4. **PR 4 — Drop schema + sync services** (Phase 4 + 5): migration `0004`, delete sync code, delete obsolete tests, add Phase 5.3 E2E, regenerate bundle.
5. **PR 5 — Docs** (Phase 6).

Each PR independently shippable + revertible. PR 1-2 are zero-behavior-change.

---

## Open Questions

1. Keep read-only `/admin/collections` page (list code-defined collections) or drop entirely? → Recommendation: keep read-only — useful for editors picking collection at content creation.
2. Form.io plugin: does it actually need `collections` rows, or only `documents`? → Investigate in Phase 4.2 before deleting `form-collection-sync.ts`.
3. One-shot export CLI for existing installs? → Skip for POC. Revisit pre-v3 GA if there's an install base.

---

## Done When

- [ ] All 5 PRs merged to v3.
- [ ] `grep -r "FROM collections" packages/core/src` → 0 results.
- [ ] `collections` table absent from `packages/core/migrations/*.sql` final state.
- [ ] `npm test` + `npm run e2e` green.
- [ ] Code-config registration path documented in CLAUDE.md + getting-started.
- [ ] No regression in `/admin/content` create/list/filter flows.
