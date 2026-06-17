# Plan: Versioning Off by Default + Versioning Plugin

**Status:** Plan only. Not started.
**Target branch:** `origin/v3`
**Intended implementer:** cheaper coding model (Sonnet/Haiku). Steps are spelled out with exact files, signatures, SQL, bind counts, and tests so no architectural judgment is required.

---

## 1. Goal

Many CMS use cases never need content version history. Today the document model **always** versions:

- Every `DocumentsService.saveDraft()` **inserts a new `documents` row** (`version_number++`, `version_of_id` chain), demotes the prior draft, then prunes to `maxVersionsPerRoot` (default 50).
- `DocumentsService.publish()` leaves the **superseded published row behind as a history row** (clears `is_published`, keeps the row).
- `DocumentRepository.getVersionHistory(rootId)` returns every retained version row.

We want:

1. **Versioning OFF by default.** New installs/types accumulate no history. Editing reuses one working row; superseding deletes the old live row.
2. **Versioning as an opt-in plugin.** The history *feature* (retention + history UI + restore) ships as a `versioning-plugin`. Installing it and opting a type in restores today's behavior for that type.

### Non-goals (explicitly out of scope)

- Removing the two-axis draft/published model. `is_current_draft` and `is_published` stay separate so "edit a draft while the published copy stays live" keeps working. We only stop **history accumulation**, not the draft buffer.
- A schema migration. The toggle is a JSON key in the existing `document_types.settings` blob — **no new column, no migration file, no `migrations-bundle.ts` regen** (avoids R9).
- Touching legacy `content_versions` behavior except to delete confirmed dead code (see §6).

---

## 2. Semantics: what "versioning off" means (the precise contract)

Per document **type**, a boolean `settings.versioning` (default `false`).

### When `versioning === false` (default)

| Operation | Behavior |
|---|---|
| `create` | Unchanged. One row, `version_number = 1`. |
| `saveDraft` on a draft row that is **not** also the published row | **UPDATE that row in place.** No new row. `version_number`, `id`, `root_id`, `version_of_id` unchanged. Derived rows (`document_facets`, `document_references`) rebuilt for the row. |
| `saveDraft` on a row that **is** the live published row | Fall back to inserting **one** new draft row (today's path) so the published copy stays live. This happens at most once per publish cycle — the next `saveDraft` hits the in-place branch. |
| `publish` superseding a **separate** old published row | **DELETE** the old published row + its derived rows (instead of leaving it as history), unless that row is the current draft. |
| `unpublish` | Unchanged. |

**Steady state with versioning off:** at most **2 rows per root** — one published-live row + one working draft — never growing. History never accumulates.

### When `versioning === true` (plugin opts the type in)

Exactly today's behavior: new row per `saveDraft`, `version_of_id` chain, prune to `maxVersionsPerRoot`, superseded published rows retained as history, `getVersionHistory` returns them.

### Invariants preserved in BOTH modes (do not break)

- Partial unique indexes from `0002_documents.sql`: one `is_current_draft=1` per root, one `is_published=1` per root, unique `(root_id, version_number)`, unique current-draft slug. In-place UPDATE keeps the same row so all four stay satisfied trivially.
- R3 tenant scoping: every statement carries `AND tenant_id = ?`.
- R7: derived rows exist only for current-draft/published rows. In-place UPDATE must delete-then-reinsert the row's derived rows so facets/refs track the new `data`.
- Timestamps in **seconds** (R/CLAUDE: `documentSecondsToMs`).

---

## 3. Architecture decision (why this split)

- The **write behavior** (new-row vs in-place) lives in core `DocumentsService` because no lifecycle hook fires on document writes (verified — `saveDraft`/`publish` are pure DB, no `executeHook`). A plugin cannot inject write behavior, so **core must contain both code paths**, gated by the per-type flag.
- The **plugin's job** is therefore: (a) flip `settings.versioning = true` on the types its config names, and (b) expose the read-only history UI + restore action. With no plugin installed, every type stays `versioning:false` → no history rows, no UI. This is the honest, minimal split.

```
core (always present)            versioning-plugin (optional)
─────────────────────            ────────────────────────────
settings.versioning flag   ◄──── boot: set versioning=true on configured types
saveDraft: in-place | new-row    admin routes: GET history, POST restore
publish:   delete | retain       edit-form panel + nav item
getVersionHistory (read)         maxVersionsPerRoot config UI
```

---

## 4. Phase 1 — Core changes (cheap-model executable)

All paths relative to `packages/core/src/`. **No migration, no bundle regen.**

### 4.1 Add the flag to the settings type

File: `schemas/document.ts`, interface `DocumentTypeSettings` (~line 19).

Add:

```ts
  /**
   * Retain historical version rows for this type. Default false.
   * When false: saveDraft updates the working draft row in place and publish deletes the
   * superseded published row (at most ~2 rows per root, no history accumulation).
   * When true: new row per saveDraft + prune to maxVersionsPerRoot (the versioning-plugin opts types in).
   */
  versioning?: boolean
```

### 4.2 Thread the flag into the service

File: `services/documents.ts`.

1. `DocumentsServiceOptions` (~line 59) — add:

```ts
  /** Retain version history (new row per saveDraft, supersede-as-history). Default false (in-place). */
  versioning?: boolean
```

2. In the constructor store it: `private versioning: boolean` set from `opts.versioning ?? false`.

3. `makeDocService` in `routes/admin-content.ts` (~line 417) — add to the options object:

```ts
    versioning: docType.settings?.versioning ?? false,
```

   Do the same wherever else a `DocumentsService` is constructed from a doc type's settings. **Grep for `new DocumentsService(` and check each call site** (currently: `routes/admin-content.ts`, `routes/admin-documents.ts`, `routes/api-content-crud.ts` via shared helper, plus tests). Pass `versioning` through from `settings.versioning`.

### 4.3 Branch `saveDraft`

File: `services/documents.ts`, `saveDraft` (~line 151).

After fetching `prevDraftRow` / computing `prevIsPublished` (line ~193), insert the branch:

```ts
    // Versioning off + the working draft is a pure draft (not the live published row):
    // update it in place. No new row, no history accumulation. (R7: rebuild derived rows.)
    if (!this.versioning && !prevIsPublished) {
      return this.updateInPlace(prevDraft, input, now, updatedBy)
    }
```

Everything below that branch (demote + insert new row + prune) stays as the versioned / published-fallback path.

### 4.4 New method `updateInPlace`

File: `services/documents.ts`. Add a private method. **R1**: raw `prepare/bind/batch`. **R5**: count binds by hand (comment below lists them).

```ts
  // In-place draft update (versioning off). Mutates the existing draft row; preserves id/root_id/
  // version_number/version_of_id and the is_current_draft/is_published flags. Rebuilds derived rows.
  private async updateInPlace(
    prevDraft: Document,
    input: UpdateDocumentInput,
    now: number,
    updatedBy?: string,
  ): Promise<Document> {
    const mergedData = { ...prevDraft.data, ...(input.data ?? {}) }
    const mergedMeta = { ...prevDraft.metadata, ...(input.metadata ?? {}) }

    const updated: Document = {
      ...prevDraft,
      slug: input.slug !== undefined ? input.slug ?? null : prevDraft.slug,
      title: input.title !== undefined ? input.title ?? null : prevDraft.title,
      zone: input.zone !== undefined ? input.zone ?? null : prevDraft.zone,
      sortOrder: input.sortOrder ?? prevDraft.sortOrder,
      visible: input.visible ?? prevDraft.visible,
      scheduledAt: input.scheduledAt !== undefined ? input.scheduledAt : prevDraft.scheduledAt,
      expiresAt: input.expiresAt !== undefined ? input.expiresAt : prevDraft.expiresAt,
      data: mergedData,
      metadata: mergedMeta,
      updatedBy: updatedBy ?? prevDraft.updatedBy,
      updatedAt: now,
    }

    const statements: D1PreparedStatement[] = [
      // R5: 11 SET '?' + 2 WHERE '?' (id, tenant_id) = 13 binds, matching .bind() below.
      this.db.prepare(
        `UPDATE documents SET
           slug = ?, title = ?, zone = ?, sort_order = ?, visible = ?,
           scheduled_at = ?, expires_at = ?, data = ?, metadata = ?, updated_by = ?, updated_at = ?
         WHERE id = ? AND tenant_id = ?`,
      ).bind(
        updated.slug, updated.title, updated.zone, updated.sortOrder, updated.visible ? 1 : 0,
        updated.scheduledAt, updated.expiresAt, JSON.stringify(updated.data), JSON.stringify(updated.metadata),
        updated.updatedBy, now,
        updated.id, this.tenantId,
      ),
      // R7: derived rows track the new data — delete then reinsert for this row.
      ...this.projection.buildDerivedDeleteStatements(updated.id),
      ...this.projection.buildDerivedInsertStatements(updated, this.opts.queryableFields ?? [], now),
    ]

    await this.db.batch(statements)

    const saved = await this.db.prepare('SELECT * FROM documents WHERE id = ?').bind(updated.id).first<DocumentRow>()
    return rowToDocument(saved!)
  }
```

> Note: `rowToDocument` is the module-private helper already in `documents.ts` (line ~24). Reuse it.

### 4.5 Branch `publish` to delete superseded history

File: `services/documents.ts`, `publish` (~line 258), the `if (prevPublishedRow) { ... }` block (~line 275).

When `!this.versioning`, **delete** the superseded published row instead of leaving it as history:

```ts
    if (prevPublishedRow) {
      if (!this.versioning && prevPublishedRow.is_current_draft !== 1) {
        // Versioning off: old published row is pure history — remove it + its derived rows.
        statements.push(...this.projection.buildDerivedDeleteStatements(prevPublishedRow.id))
        statements.push(this.db.prepare('DELETE FROM documents WHERE id = ? AND tenant_id = ?')
          .bind(prevPublishedRow.id, this.tenantId))
      } else {
        // existing behavior: clear is_published, drop derived rows if not the current draft
        statements.push(
          this.db.prepare('UPDATE documents SET is_published = 0, updated_at = ? WHERE id = ?')
            .bind(now, prevPublishedRow.id),
        )
        if (prevPublishedRow.is_current_draft !== 1) {
          statements.push(...this.projection.buildDerivedDeleteStatements(prevPublishedRow.id))
        }
      }
    }
```

> Guard against the FK `version_of_id` RESTRICT: with versioning off there is no `version_of_id` chain pointing at the old published row (in-place edits don't create chains), so the delete is safe. The new-draft fallback in §2 sets `version_of_id = prevDraft.id` only when the prev draft was published — that chained child becomes the new published row and is not deleted. **Add a sqlite test that publishes twice with versioning off and asserts no FK error** (§4.7).

### 4.6 `getVersionHistory` — leave as-is

Returns whatever rows exist. With versioning off, that's just the live rows (1–2). No change needed; the plugin's UI simply shows little. Optionally short-circuit for clarity, but not required.

### 4.7 Tests (R10 — real sqlite harness, NOT mocks)

File: `__tests__/services/documents.sqlite.test.ts` (extend existing). Add a `describe('versioning off', ...)` block:

1. **In-place edit keeps one row.** Create a type with `versioning:false`. `create` → `saveDraft` → `saveDraft`. Assert `SELECT COUNT(*) FROM documents WHERE root_id=?` stays `1`, `version_number` unchanged, latest `data` reflects the last save.
2. **Derived rows rebuilt.** Type with a `tags` facet + a queryable `q_*` field. saveDraft changing tags → assert `document_facets` for the row match the new tags (no stale rows).
3. **Publish deletes superseded history.** create → publish → saveDraft (spawns draft) → publish again. Assert exactly **1** `is_published=1` row and total rows `<= 2`; assert **no FK error**.
4. **Draft-while-published still works.** Publish, then saveDraft → assert a separate draft row exists, published row's `data` unchanged (live copy intact).
5. **Regression: `versioning:true` unchanged.** Same sequence with `versioning:true` accumulates history rows and `getVersionHistory` returns them (guards the plugin path).
6. **maxVersionsPerRoot irrelevant when off.** With `versioning:false`, 60 saves still leave `<= 2` rows.

Run: `npm test -- documents.sqlite`.

---

## 5. Phase 2 — `versioning-plugin`

Location: `packages/core/src/plugins/core-plugins/versioning-plugin/`. Mirror the structure of an existing core-plugin (e.g. `security-audit-plugin/` or `user-profiles/`). Register it in the core-plugins index the same way siblings are registered.

### 5.1 Plugin config

```ts
interface VersioningPluginConfig {
  /** Type IDs to version. Ignored if versionAll. */
  versionedTypes?: string[]
  /** Version every content type. Default false. */
  versionAll?: boolean
  /** Default retention when a type doesn't set its own. */
  defaultMaxVersionsPerRoot?: number // default 50
}
```

### 5.2 Boot: flip the flag on configured types

In the plugin's boot/activate hook, for each configured type, ensure `settings.versioning = true` (and `maxVersionsPerRoot` if provided). Two mechanisms — pick the one that matches how the type was registered:

- **Code/plugin-owned types:** they already register via `onBoot`/`bootstrapDocumentTypes`. The versioning-plugin runs **after** them in bootstrap order and patches the registered `document_types.settings` JSON: `UPDATE document_types SET settings = json_set(settings,'$.versioning', json('true')) WHERE id IN (...)` (tenant-agnostic; `document_types` is global). Confirm ordering against `middleware/bootstrap.ts` — versioning-plugin `onBoot` must run after `autoRegisterCollectionDocumentTypes` + `bootstrapDocumentTypes`.
- **Collection-driven types:** same `UPDATE` keyed by the collection name (== type id).

> The flag is read at request time in `makeDocService` (`docType.settings?.versioning`), so patching the stored `settings` is sufficient — no service-construction change beyond §4.2.

### 5.3 Admin routes (read + restore)

The plugin owns the history surface. Core `admin-documents.ts` already has `GET /:rootId/versions` returning `getVersionHistory`; **move/duplicate** the user-facing history + restore endpoints into the plugin (or keep the JSON read in core and add the HTML UI + restore in the plugin — recommended: keep core's JSON `getVersionHistory` endpoint, add plugin UI on top).

Plugin endpoints:

- `GET /admin/versioning/:typeId/:rootId` — render history list (uses `DocumentRepository.getVersionHistory`, R4 — no inline SQL). Escape all rendered data with `escapeHtml` (R8).
- `POST /admin/versioning/:typeId/:rootId/restore/:versionNumber` — load that version row's `data`, then call `DocumentsService.saveDraft(rootId, { data, title, slug })` to make it the new working draft (works in both modes; ACL-gated via `denyIfNotAllowed`).

### 5.4 UI surface

- A "Version History" panel/button on the content edit form, shown **only when the type has `versioning:true`**. Gate the template include on `docType.settings?.versioning`.
- A nav/menu item (`menuItems` in the Plugin interface) if a standalone history browser is desired. Optional.
- Reuse a document-version-shaped template (see §6 — the existing `version-history.template.ts` is `content_versions`-shaped; either adapt it to `Document[]` rows or write a small new one in the plugin dir).

### 5.5 Plugin tests

- `*.integration.test.ts` (route harness): with the plugin active and a type opted in, `saveDraft` accumulates history and `GET .../versions` lists it; restore creates a new current draft with the old data.
- With the plugin **inactive**, the same type stays `versioning:false` and history does not accumulate (guards the default-off contract end to end).

---

## 6. Phase 3 — Cleanup of dead legacy version code

The legacy `content_versions` path is **already dead** (verified):

- `routes/admin-content.ts` `GET /:id/versions` (~line 1929) returns `c.html('<p>Content not found</p>', 404)` before any logic.
- `routes/admin-content.ts` `POST /:id/restore/:version` (~line 1983) returns `404` before any logic.
- Both reference the legacy `content_versions` table and the `content` table (being decommissioned).

Action: **delete** both dead handlers and the now-unused import on `routes/admin-content.ts:9` (`ContentVersion, renderVersionHistory, VersionHistoryData` from `version-history.template`). If `version-history.template.ts` has no other importer after the plugin uses its own template, delete it too (grep first). This is pure dead-code removal — keep it a separate commit from the feature so review is clean. Do **not** touch the legacy `content`/`content_versions` tables themselves (R12 — decommission separately).

---

## 7. Phase 4 — E2E (mandatory, R11: number 68+)

Add `tests/e2e/<NN>-versioning-optional.spec.ts` (NN = next sequential ≥ 68). Cover:

1. **Default off:** create a content item (type with no versioning), edit it twice, confirm only the latest content shows and no version-history UI is present.
2. **Plugin on:** with a type opted into versioning, edit twice → version-history panel lists multiple versions → restore an earlier version → confirm content reverts and a new current version is created.
3. **Publish/edit/publish with versioning off:** publish, edit (draft), publish again → live content updates, no history piles up, no error.

Run: `npx playwright test tests/e2e/<NN>-versioning-optional.spec.ts`.

---

## 8. File-touch summary (for the implementer)

| File | Change | Phase |
|---|---|---|
| `schemas/document.ts` | add `versioning?: boolean` to `DocumentTypeSettings` | 1 |
| `services/documents.ts` | `DocumentsServiceOptions.versioning`; store on instance; branch `saveDraft` → `updateInPlace`; new `updateInPlace`; branch `publish` delete-supersede | 1 |
| `routes/admin-content.ts` | thread `versioning` in `makeDocService`; delete dead `content_versions` routes + unused import | 1 / 3 |
| `routes/admin-documents.ts`, `routes/api-content-crud.ts` (+ helper) | thread `versioning` at every `new DocumentsService(` site | 1 |
| `__tests__/services/documents.sqlite.test.ts` | versioning-off + regression tests (R10) | 1 |
| `plugins/core-plugins/versioning-plugin/**` | new plugin: config, boot flag-flip, history+restore routes, UI panel, template | 2 |
| core-plugins index | register `versioning-plugin` | 2 |
| `*.integration.test.ts` | plugin on/off route tests | 2 |
| `templates/components/version-history.template.ts` | adapt for `Document[]` or delete if unused | 2 / 3 |
| `tests/e2e/<NN>-versioning-optional.spec.ts` | E2E (R11, ≥68) | 4 |

**No** changes to: `migrations/*.sql`, `migrations-bundle.ts`, `db/schema.ts`. The toggle is JSON in `document_types.settings` → no migration, no R9 regen.

---

## 9. Risks / gotchas

1. **FK `version_of_id` RESTRICT on publish-delete (§4.5).** Only delete the superseded published row when nothing references it. With versioning off, in-place edits create no chains, so it's safe — but the new-draft fallback path *does* set `version_of_id`. Sqlite test #3 must publish twice to exercise this. If an FK error ever surfaces, null out children first: `UPDATE documents SET version_of_id = NULL WHERE version_of_id = ?` before the delete.
2. **Bind-count drift (R5).** `updateInPlace` UPDATE = 13 binds. Recount if columns change. Mocks won't catch it (R10) — rely on the sqlite harness.
3. **Slug uniqueness.** In-place keeps the same row, so the current-draft slug unique index stays satisfied even when the slug changes. No special handling.
4. **Migrating an existing root from versioned→unversioned (or back).** Flipping the flag does not retro-delete existing history rows; it only changes future behavior. Document this. A cleanup script (delete non-current/non-published rows for a root) can be added later if desired — out of scope here.
5. **Bootstrap ordering.** The plugin's flag-flip `UPDATE document_types` must run after types are registered. Verify against `middleware/bootstrap.ts` order before wiring (Phase 2).
6. **Other `new DocumentsService(` call sites.** Grep before finishing Phase 1 — any site that omits `versioning` silently defaults to `false`, which is correct for the default but wrong if that site backs a versioned type. Thread it from settings everywhere.

---

## 10. Verification checklist

```bash
cd packages/core && npm run type-check
npm test -- documents.sqlite          # Phase 1 unit/real-DB
npm test -- versioning                 # Phase 2 plugin integration
npm run e2e -- tests/e2e/<NN>-versioning-optional.spec.ts
```

- [ ] Default type: zero history rows after N edits (`COUNT(*) <= 2` per root).
- [ ] Publish/edit/publish off: 1 published row, no FK error, live content correct.
- [ ] Plugin on + type opted in: history accumulates, restore works.
- [ ] `versioning:true` regression suite green (no behavior change for opted-in types).
- [ ] No migration / bundle changes in the diff.

---

## 11. Review section

### Enablement decision: Option A (per-type setting in code)

§5.2 originally proposed a runtime `UPDATE document_types` flag-flip. We chose **Option A** instead: a
type opts into versioning by setting `settings.versioning: true` in its code definition (collection/seed
or plugin onBoot). No DB patching, no bootstrap-ordering coupling. The `versioning-plugin` owns only the
history/restore UI + routes; with no opted-in type, nothing accumulates and nothing shows.

### What shipped

**Phase 1 — core, default-off**
- `schemas/document.ts`: `versioning?: boolean` on `DocumentTypeSettings` (default false).
- `services/documents.ts`: service option + `saveDraft` in-place branch + `updateInPlace` (13-bind UPDATE, R5)
  + `publish` delete-supersede branch. Added a `version_of_id` null-out before the supersede DELETE so the
  create→publish→edit→publish chain can't trip the FK RESTRICT (plan risk #1).
- Threaded `versioning` from settings at all 9 doc-type `new DocumentsService(` sites
  (`admin-content.ts`, `admin-documents.ts`, `api-content-crud.ts`, `api.ts`).
- 6 real-SQLite "versioning off" tests + a `versioning:true` regression guard.

**Phase 2 — versioning-plugin (Option A)**
- `plugins/core-plugins/versioning-plugin/` (`index.ts` definePlugin, `routes.ts`, `manifest.json`):
  `GET /admin/versioning/:rootId` (history panel HTML, ACL read, escapeHtml R8) and
  `POST /admin/versioning/:rootId/restore/:versionNumber` (ACL update → saveDraft restore). Reuses
  exported `resolveDocScope`/`denyIfNotAllowed` from `admin-documents.ts`.
- Registered: export from `core-plugins/index.ts`, added to `corePluginsBeforeCatchAll` in `app.ts`.
- Edit-form integration: `ContentFormData.versioningEnabled` gate on the existing "View Version History"
  button (was always shown, wired to a dead route); `showVersionHistory` JS + the documents-form HTMX
  repointed to `/admin/versioning/:rootId`. `admin-content.ts` sets `versioningEnabled` on the two
  doc-backed edit formData sites.
- `blog_post` seed opts in (`settings.versioning: true`) as the Option A showcase.
- 4 plugin integration tests (real-SQLite harness).

**Phase 3 — cleanup**
- Deleted the dead legacy `content_versions` routes (`GET /:id/versions`, `POST /:id/restore/:version` —
  both early-returned 404) and the now-unused `version-history.template.ts` + its import.

**Phase 4 — E2E**
- `tests/e2e/81-versioning-optional.spec.ts` (floor was 80, not 68): create → 2 edits → assert history
  lists v1–v3 + Restore → restore v1 creates v4; edit form shows the button for the versioned type;
  unknown root → 404.

### Verification
- `npm run type-check` (core): clean.
- Versioning unit/integration tests: 6/6 (sqlite off) + 4/4 (plugin) pass.
- Pre-existing unrelated failures remain (broken integration harness: `no such table: users`; `q_*`
  generated columns absent in the better-sqlite3 shim) — confirmed independent of these changes.
- E2E (`81-versioning-optional.spec.ts`): **3/3 pass** against the live dev server. NOTE: this Conductor
  workspace's dev server binds a dir-name-derived port (`philadelphia-v1` → **9176**), not 8787 — run E2E
  with `BASE_URL=http://localhost:9176` (Playwright then skips its own webServer and uses the running one).
  Local D1 must be set up first: `cd my-sonicjs-app && npm run setup:db`.

### Follow-ups / notes
- Restore uses `saveDraft`, which **merges** the old version's data over the current draft (keys added
  after that version persist). Acceptable for v1; a true replace-restore would clear unknown keys.
- No migration / `migrations-bundle.ts` / `schema.ts` changes — the toggle is JSON in
  `document_types.settings`.
- Switching a type from versioned→unversioned does not retro-delete existing history rows; only future
  writes change. A cleanup script could be added if needed.
