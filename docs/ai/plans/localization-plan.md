# SonicJS v3 Localization — Evaluation & Implementation Plan

## 1. Current state on v3 (validated)

### Data model — DONE, dormant
The `documents` table (migration `0002_documents.sql`) already carries every column localization needs:

- `locale TEXT NOT NULL DEFAULT 'default'` — per-document language.
- `translation_group_id TEXT NOT NULL DEFAULT ''` — links sibling translations of the same logical content.
- `idx_documents_translation` on `(translation_group_id, locale)` — fast "find all translations of X".
- `idx_documents_one_translation_per_locale` — UNIQUE on `(tenant_id, translation_group_id, locale)` WHERE `is_current_draft = 1 AND translation_group_id <> ''`. Hard guarantee: at most one draft per locale per group.
- `idx_documents_unique_slug` — slug uniqueness is **already locale-scoped** `(tenant_id, locale, type_id, parent_root_id, slug)`. So `/about` (en) and `/about` (es) can coexist or differ per locale.
- `idx_documents_published` includes `locale` in its key.

**Conclusion: table structure is in place and correct. No schema migration required for the core data model.**

### Service layer — partial / dormant
- `DocumentsService.create()` (services/documents.ts:113) stores `locale` from input — works.
- BUT `translationGroupId` is **hardcoded to `''`** on both create (`:114`, `:135`) and never derived on `saveDraft` (carries prev value, which is also `''`). Nothing ever links a translation to its source.
- `DocumentRepository` (services/document-repository.ts:139) **supports** filtering published lists by `locale` — already wired.
- No API to: create-a-translation-of, list-translations-of, or switch the working locale.

### Admin / API routes — locale hardcoded
- `routes/admin-content.ts` and `api-content-crud.ts` pass `locale: 'default'` literally everywhere (admin-content.ts:1179, 1596, 2175). No locale selection threads through create/edit/list.
- No locale switcher, language column, or "translate" action in any admin template.

### Settings — single value only
- `GeneralSettings.language` (services/settings.ts:15) is one site language string. No concept of an enabled-locales list, default locale, or fallback chain.

### Plugin system — ready to host this
Plugin SDK (`plugins/sdk/plugin-builder.ts`) exposes everything needed:
`addRoute`, `addAdminPage`, `addMenuItem`, `addService`, `addHook` (content lifecycle hooks: `CONTENT_CREATE`, `CONTENT_SAVE`, `CONTENT_PUBLISH`), `lifecycle` (`install`/`activate` for migrations + seeding). Document types register via `DocumentTypeRegistry.register()` (idempotent, `source: 'plugin'`). Plugins mount admin pages + menu items dynamically.

**Verdict: foundation is ~40% there. Data model done; linking logic, locale-aware routing, config, and all admin UI are missing. All missing parts can live in a plugin — only the (already-present) columns and indexes are core.**

---

## 2. Why a plugin, not core
- Columns/indexes already shipped in core migrations — zero marginal cost, dormant for users who don't localize.
- All *behavior* (translation linking, locale switching, config, UI) is opt-in. Devs who don't need i18n never see it.
- Plugin owns: a `locale_config` settings record, admin UI pages/menu, a `LocalizationService`, content-lifecycle hooks, and request middleware for locale resolution.

Plugin name: `localization-plugin` under `packages/core/src/plugins/available/` (matches `magic-link-auth`, `email-templates-plugin` convention — available = opt-in, not auto-loaded).

---

## 3. Plugin architecture

### 3.1 Config (stored via SettingsService, category `localization`)
```ts
interface LocalizationConfig {
  enabled: boolean
  defaultLocale: string          // e.g. 'en'
  locales: LocaleDef[]           // enabled set
  fallbackLocale: string         // resolution fallback
  showLocaleColumn: boolean      // admin list toggle
  routingStrategy: 'none' | 'prefix' | 'domain'  // future public routing
}
interface LocaleDef { code: string; label: string; nativeLabel?: string; rtl?: boolean; enabled: boolean }
```
Seeded on `activate` with `{ defaultLocale: 'en', locales: [en] }`.

### 3.2 LocalizationService (new, `addService`)
- `listLocales()` / `getConfig()` / `saveConfig()`.
- `createTranslation(rootId, targetLocale, { copyContent })`: loads source current-draft doc, mints a new document with same `type_id`/`tenant_id`, **assigns/propagates `translation_group_id`** (see §3.3), `locale = targetLocale`, optionally copies `data` for translator to edit. Respects the unique-per-locale index (reject if target locale already exists in group).
- `getTranslations(rootId)`: resolve group id → all sibling docs grouped by locale + their status (missing / draft / published).
- `getTranslationStatus(typeId)`: matrix for the admin list (which locales exist for each group).

### 3.3 Translation-group linking — the core fix
The single most important behavior gap. Two options:

**Option A (recommended): lazy group creation.**
- Original doc keeps `translation_group_id = ''` until a *second* locale is added.
- On first `createTranslation`, set `translation_group_id = root_id` of the source on BOTH source and new doc (one UPDATE + the insert). Group id = the first root's id — stable, no extra table.
- All later translations inherit that same group id.

**Option B: always-on group id** = mint group id at document create. Cleaner but requires touching core `DocumentsService.create` (the hardcoded `''`). Avoid — keeps logic in plugin.

Go with **A**. It needs only an UPDATE on the source's current-draft row (and ideally all its version rows for consistency), done inside the plugin service via `db.batch`. Note the unique index only enforces when `translation_group_id <> ''`, so `''`-grouped originals are unaffected.

Caveat to handle: `idx_documents_one_translation_per_locale` is scoped to `is_current_draft = 1`. `saveDraft` mints a new draft row that must **carry the group id forward** — it already copies `translationGroupId` from prev draft (documents.ts:168 spread), so once set it propagates. Verify in tests.

### 3.4 Hooks
- `CONTENT_SAVE` / `CONTENT_CREATE` (optional): no linking by default (linking is explicit via UI action), but hook can stamp `metadata.sourceLocale` for translator context.
- Request middleware: resolve active locale from `?locale=`, cookie, or `Accept-Language`, expose on context for public API filtering.

### 3.5 Public API
- Extend (or wrap) content list endpoints to accept `?locale=xx` → `DocumentRepository` already filters by locale. Add fallback: if no doc in requested locale, optionally serve `fallbackLocale` version (resolve via group id).

---

## 4. Admin UI elements needed

### 4.1 Localization settings page (`/admin/localization`, menu item, icon `globe`)
- Enable/disable localization.
- Default locale selector.
- Enabled-locales manager: add/remove locale (code + label + RTL flag), reorder, set fallback.
- Routing strategy (future).
Pattern: copy `admin-plugin-settings.template.ts` / `admin-settings.template.ts` form structure.

### 4.2 Locale switcher in content list (`admin-content-list.template.ts`)
- Dropdown in the list toolbar: "Viewing: [English ▾]". Changes `?locale=` query → list filters by that locale.
- New **"Languages" column** (gated by `showLocaleColumn`): per row, badges showing which locales exist — green = published, yellow = draft, grey/＋ = missing (click to create translation). This is the at-a-glance translation matrix.

### 4.3 Content form (`admin-content-form.template.ts`)
- Locale indicator/badge in the header ("Editing: Español").
- **"Translations" panel** (sidebar): list sibling locales with status; each row links to that translation's edit page, or a "Translate to …" button that calls `createTranslation` and opens the new draft.
- "Translate this" action that spawns drafts for missing locales (optionally pre-filled from source `data`).

### 4.4 New-content flow
- When localization enabled, "New" respects the currently-selected locale; the created doc gets that `locale`.

### 4.5 Menu
- `addMenuItem('Localization', '/admin/localization', { icon: 'globe', order: 95, permissions: ['admin'] })`.

---

## 5. File layout (proposed)
```
packages/core/src/plugins/available/localization-plugin/
  index.ts                      # createLocalizationPlugin() — builder, routes, pages, menu, hooks
  services/localization-service.ts
  routes/admin-routes.ts        # settings CRUD, createTranslation, getTranslations
  middleware/locale-resolver.ts
  templates/
    settings-page.template.ts
    translations-panel.template.ts   # reused in content form
    locale-switcher.template.ts      # reused in content list toolbar
  types.ts
```
Core touch-points (small, additive, behind `if (localizationEnabled)`):
- `admin-content.ts` list/create/edit: read `?locale=` instead of literal `'default'`; inject switcher + Languages column via plugin component or hook (`ADMIN_PAGE_RENDER`).
- Prefer rendering UI via plugin `adminComponents` + the existing admin render hooks so core templates stay clean.

---

## 6. Build order (phased)
1. **Plugin skeleton + config**: builder, settings page, enabled-locales manager, menu item. (No content behavior yet.) E2E: enable plugin, add locales, persist.
2. **LocalizationService + translation linking** (Option A group ids) + admin routes (`createTranslation`, `getTranslations`). Unit/SQLite tests on group-id propagation through `saveDraft`/`publish` and the unique-per-locale index.
3. **Content list UI**: locale switcher + Languages column; thread `?locale=` through `admin-content.ts` list.
4. **Content form UI**: translations panel + "translate to" action; locale-aware create/edit.
5. **Public API locale filter + fallback** + request middleware.
6. **Docs** + sample (add `es`, translate a blog post end-to-end).

## 7. Risks / watch-items
- `saveDraft` group-id propagation: confirm new draft rows keep `translation_group_id` (spread copies it — add a test to lock it).
- Unique index is draft-scoped; publishing a translation must not violate `idx_documents_one_published` (that's per-`root_id`, independent of group — each translation has its own root, so fine).
- Slug uniqueness is locale-scoped — good, but the "create translation" flow should default the new locale's slug (copy or localize) without colliding.
- Keep all linking logic in the plugin service; do **not** edit `DocumentsService.create`'s hardcoded `''` (would push i18n into core).
- `internal`/system doc types (`plugin`) should be excluded from translation UI.
