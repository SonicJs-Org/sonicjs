# E2E Test Consolidation Plan

**Goal:** Reduce 149 spec files (~700 tests) → ~50 files (~350 tests) while maintaining coverage  
**Estimated effort:** 3-4 days of focused work  
**Risk:** Low — tests are being merged, not deleted; coverage preserved

---

## Phase 1: Authentication Suite (6 files → 2)

### Target Files
```
tests/e2e/02-authentication.spec.ts        → KEEP (UI auth tests)
tests/e2e/02b-authentication-api.spec.ts   → MERGE into auth-api.spec.ts
tests/e2e/02c-otp-login.spec.ts            → MERGE into auth-api.spec.ts
tests/e2e/02d-magic-link-auth.spec.ts      → MERGE into auth-api.spec.ts
tests/e2e/66-auth-better-auth.spec.ts      → MERGE into auth-api.spec.ts
tests/e2e/83-login-returns-token.spec.ts   → MERGE into auth-api.spec.ts
```

### Result
```
tests/e2e/auth-ui.spec.ts      ← Playwright UI login/logout flows
tests/e2e/auth-api.spec.ts     ← All API-based auth (register, login, OTP, magic-link, tokens)
```

### Instructions
1. Create `auth-api.spec.ts` with shared setup:
   ```typescript
   import { test, expect } from '@playwright/test';
   
   test.describe('Authentication API', () => {
     test.describe('Registration', () => {
       // Move all tests from 02b-authentication-api.spec.ts registration section
     });
     
     test.describe('Login', () => {
       // Move all tests from 02b-authentication-api.spec.ts login section
     });
     
     test.describe('OTP Login', () => {
       // Move all tests from 02c-otp-login.spec.ts
     });
     
     test.describe('Magic Link', () => {
       // Move all tests from 02d-magic-link-auth.spec.ts
     });
     
     test.describe('Better Auth Integration', () => {
       // Move all tests from 66-auth-better-auth.spec.ts
     });
     
     test.describe('Token Handling', () => {
       // Move all tests from 83-login-returns-token.spec.ts
     });
   });
   ```

2. Rename `02-authentication.spec.ts` → `auth-ui.spec.ts`

3. Delete the 5 merged files

4. Run: `pnpm test:e2e --grep "auth"` to verify

---

## Phase 2: Two-Factor Auth Suite (4 files → 1)

### Target Files
```
tests/e2e/106-two-factor-auth.spec.ts           → MERGE into two-factor.spec.ts
tests/e2e/107-two-factor-admin-reset.spec.ts    → MERGE into two-factor.spec.ts
tests/e2e/108-two-factor-api-enforcement.spec.ts → MERGE into two-factor.spec.ts
tests/e2e/124-better-auth-upgrade.spec.ts       → MERGE into two-factor.spec.ts
```

### Result
```
tests/e2e/two-factor.spec.ts   ← All 2FA tests in one file
```

### Instructions
1. Create `two-factor.spec.ts`:
   ```typescript
   test.describe('Two-Factor Authentication', () => {
     test.describe('Enrollment', () => {
       // From 106: sidebar nav, QR code, password verification
     });
     
     test.describe('Challenge Flow', () => {
       // From 106: TOTP code entry, backup codes
     });
     
     test.describe('Admin Reset', () => {
       // All tests from 107
     });
     
     test.describe('API Enforcement', () => {
       // All tests from 108
     });
     
     test.describe('Better Auth Compatibility', () => {
       // 2FA-related tests from 124
     });
   });
   ```

2. Delete the 4 merged files

3. Run: `pnpm test:e2e two-factor.spec.ts`

---

## Phase 3: Media Library Suite (11 files → 3)

### Target Files
```
tests/e2e/06-media.spec.ts                → KEEP as media-core.spec.ts
tests/e2e/09-media-bulk-actions.spec.ts   → MERGE into media-core.spec.ts
tests/e2e/10-media-view-switching.spec.ts → MERGE into media-core.spec.ts
tests/e2e/17-media-upload-immediate.spec.ts → MERGE into media-upload.spec.ts
tests/e2e/18-media-bulk-menu-zindex.spec.ts → MERGE into media-core.spec.ts
tests/e2e/24-media-thumbnail-loading.spec.ts → MERGE into media-upload.spec.ts
tests/e2e/25-media-cleanup-unused.spec.ts → MERGE into media-core.spec.ts
tests/e2e/81-media-document-model.spec.ts → MERGE into media-api.spec.ts
tests/e2e/88-media-library-fixes.spec.ts  → MERGE into media-core.spec.ts
tests/e2e/91-media-upload-date.spec.ts    → MERGE into media-upload.spec.ts
tests/e2e/92-media-create-folder.spec.ts  → MERGE into media-api.spec.ts
```

### Result
```
tests/e2e/media-core.spec.ts    ← UI: library, bulk actions, views, cleanup
tests/e2e/media-upload.spec.ts  ← Upload flows, thumbnails, dates
tests/e2e/media-api.spec.ts     ← API: document model, folder creation
```

### Instructions
1. Consolidate by concern (UI vs upload vs API)
2. Share fixtures — create `tests/e2e/fixtures/media-fixtures.ts`:
   ```typescript
   export async function uploadTestImage(page: Page, filename = 'test.png') {
     // Shared upload logic
   }
   
   export async function cleanupTestMedia(request: APIRequestContext) {
     // Shared cleanup
   }
   ```
3. Each consolidated file imports fixtures
4. Delete the 8 merged files

---

## Phase 4: Plugin System Suite (22 files → 6)

### Target Files by Category

**Core Plugin Tests → plugin-core.spec.ts**
```
tests/e2e/15-plugins.spec.ts
tests/e2e/21-plugin-version-display.spec.ts
tests/e2e/28-plugin-filters-search.spec.ts
tests/e2e/68-plugin-install-click.spec.ts
tests/e2e/69-plugins-nav-accordion.spec.ts
tests/e2e/79-plugin-filter-url.spec.ts
tests/e2e/88-plugin-system.spec.ts
tests/e2e/93-disabled-plugin-sidebar.spec.ts
tests/e2e/94-removed-plugin-deactivated.spec.ts
tests/e2e/121-plugin-card-display-names.spec.ts
```

**Plugin Settings → plugin-settings.spec.ts**
```
tests/e2e/29-email-plugin-settings.spec.ts
tests/e2e/68-example-plugin-settings.spec.ts
tests/e2e/77-schema-driven-settings.spec.ts
tests/e2e/90-plugin-stale-settings-pruning.spec.ts
tests/e2e/91-plugin-routes-tab-persistence.spec.ts
tests/e2e/93-oauth-providers-settings.spec.ts
```

**Individual Plugin Tests → plugin-catalog.spec.ts**
```
tests/e2e/38-turnstile-plugin.spec.ts
tests/e2e/39-ai-search-plugin.spec.ts
tests/e2e/43-cache-plugin.spec.ts
tests/e2e/68-plugin-activity-log.spec.ts
tests/e2e/76-plugin-menu-singleton.spec.ts
tests/e2e/89-hello-cruel-world-plugin.spec.ts
```

### Result
```
tests/e2e/plugin-core.spec.ts      ← Plugin list, install, enable/disable, nav
tests/e2e/plugin-settings.spec.ts  ← Settings forms, schema-driven config
tests/e2e/plugin-catalog.spec.ts   ← Specific plugin functionality tests
```

### Instructions
1. Create shared plugin test helpers:
   ```typescript
   // tests/e2e/fixtures/plugin-fixtures.ts
   export async function ensurePluginActive(page: Page, pluginId: string) { }
   export async function ensurePluginInactive(page: Page, pluginId: string) { }
   export async function navigateToPluginSettings(page: Page, pluginId: string) { }
   ```
2. Group by concern, not by plugin
3. Use `test.describe.serial()` where plugin state matters
4. Delete the 16 merged files

---

## Phase 5: RBAC & Multi-Tenant Suite (14 files → 3)

### Target Files

**RBAC Core → rbac.spec.ts**
```
tests/e2e/67-rbac.spec.ts
tests/e2e/70-rbac-roles-verbs.spec.ts
tests/e2e/81-admin-rbac-access.spec.ts
tests/e2e/85-admin-panel-roles-naming.spec.ts
tests/e2e/95-viewer-sidebar-scope.spec.ts
tests/e2e/97-user-edit-dynamic-roles.spec.ts
tests/e2e/98-public-role-api-acl.spec.ts
tests/e2e/99-rbac-grant-api-access.spec.ts
```

**Multi-Tenant → multi-tenant.spec.ts**
```
tests/e2e/70-multi-tenant.spec.ts
tests/e2e/71-tenant-membership-gate.spec.ts
tests/e2e/72-per-tenant-roles.spec.ts
tests/e2e/73-tenant-members.spec.ts
tests/e2e/74-tenant-invitations.spec.ts
tests/e2e/75-global-document-types.spec.ts
tests/e2e/76-user-tenant-memberships.spec.ts
```

### Result
```
tests/e2e/rbac.spec.ts          ← Roles, permissions, access control
tests/e2e/multi-tenant.spec.ts  ← Tenant CRUD, membership, isolation
```

### Instructions
1. Multi-tenant tests MUST run serially (state-dependent)
2. Add shared setup/teardown:
   ```typescript
   test.beforeAll(async ({ request }) => {
     // Enable multi-tenant plugin
   });
   
   test.afterAll(async ({ request }) => {
     // Disable multi-tenant plugin to restore baseline
   });
   ```
3. Each file in multi-tenant currently has its own teardown — consolidate to one `afterAll`
4. Delete the 12 merged files

---

## Phase 6: Content & Forms Suite (18 files → 5)

### Target Files

**Content CRUD → content-crud.spec.ts**
```
tests/e2e/05-content.spec.ts
tests/e2e/23-content-api-crud.spec.ts
tests/e2e/26-content-duplicate.spec.ts
tests/e2e/42-content-deletion-bug.spec.ts
tests/e2e/62-public-content-api-status-visibility.spec.ts
tests/e2e/63-document-blog-crud.spec.ts
tests/e2e/100-content-title-preserved-on-edit.spec.ts
tests/e2e/125-content-delete-confirmation-page.spec.ts
```

**Content Forms → content-forms.spec.ts**
```
tests/e2e/19-content-media-selector.spec.ts
tests/e2e/39-slug-generation.spec.ts
tests/e2e/54-hero-cta-style-persistence.spec.ts
tests/e2e/55-collapsible-state-persistence.spec.ts
tests/e2e/56-collapsible-validation-visibility.spec.ts
tests/e2e/117-content-form-no-htmx.spec.ts
tests/e2e/118-content-save-and-close.spec.ts
tests/e2e/122-content-form-no-background-write.spec.ts
```

**Content Serialization → content-serialization.spec.ts**
```
tests/e2e/57-nested-array-serialization-scope.spec.ts
tests/e2e/58-nested-object-serialization.spec.ts
tests/e2e/59-array-media-picker-targeting.spec.ts
```

**Forms Builder → forms.spec.ts**
```
tests/e2e/50-forms.spec.ts
tests/e2e/51-turnstile-integration.spec.ts
tests/e2e/52-forms-smoke.spec.ts
tests/e2e/53-forms-as-content.spec.ts
```

### Result
```
tests/e2e/content-crud.spec.ts          ← Create, read, update, delete
tests/e2e/content-forms.spec.ts         ← Form UI, validation, persistence
tests/e2e/content-serialization.spec.ts ← Nested arrays, objects, blocks
tests/e2e/forms.spec.ts                 ← Forms builder feature
```

---

## Phase 7: Cache Suite (4 files → 1)

### Target Files
```
tests/e2e/43-cache-plugin.spec.ts           → MERGE
tests/e2e/80-cache-warming-documents.spec.ts → MERGE
tests/e2e/81-cache-collection-settings.spec.ts → MERGE
tests/e2e/97-cache-invalidation.spec.ts     → MERGE
```

### Result
```
tests/e2e/cache.spec.ts   ← All cache tests
```

---

## Phase 8: Rich Text Editors Suite (6 files → 2)

### Target Files
```
tests/e2e/30-richtext-tinymce.spec.ts    → MERGE into richtext.spec.ts
tests/e2e/31-richtext-quill.spec.ts      → MERGE into richtext.spec.ts
tests/e2e/32-mdxeditor-new-content.spec.ts → MERGE into richtext.spec.ts
tests/e2e/32-mdxeditor-richtext.spec.ts  → MERGE into richtext.spec.ts
tests/e2e/36-easymde-plugin-visible.spec.ts → MERGE into richtext.spec.ts
tests/e2e/77-lexical-editor.spec.ts      → MERGE into richtext.spec.ts
```

### Result
```
tests/e2e/richtext.spec.ts   ← All editor tests with describe blocks per editor
```

---

## Phase 9: Remaining Files (Keep As-Is or Minor Merges)

### Keep Standalone (essential, low overlap)
```
tests/e2e/smoke.spec.ts                    ← KEEP (entry point smoke)
tests/e2e/01-health.spec.ts                ← KEEP
tests/e2e/03-admin-dashboard.spec.ts       ← KEEP
tests/e2e/07-api.spec.ts                   ← KEEP
tests/e2e/09-integration.spec.ts           ← KEEP
tests/e2e/13-migrations.spec.ts            ← KEEP
tests/e2e/14-database-tools.spec.ts        ← KEEP
tests/e2e/100-graphql.spec.ts              ← KEEP
tests/e2e/94-self-host-smoke.spec.ts       ← KEEP
tests/e2e/96-mcp-endpoint.spec.ts          ← KEEP
```

### Minor Merges

**User Management → users.spec.ts**
```
tests/e2e/15-user-xss-prevention.spec.ts
tests/e2e/16-user-management.spec.ts
tests/e2e/27-profile-picture-upload.spec.ts
tests/e2e/78-author-user-search.spec.ts
tests/e2e/80-user-profile-code-config.spec.ts
tests/e2e/115-admin-set-password.spec.ts
tests/e2e/116-register-credential.spec.ts
```

**Collections → collections.spec.ts**
```
tests/e2e/33-field-type-editor-options.spec.ts
tests/e2e/34-field-type-persistence.spec.ts
tests/e2e/35-collection-field-type-badges.spec.ts
tests/e2e/36-collection-field-easymdx-edit.spec.ts
tests/e2e/70-collection-registry.spec.ts
tests/e2e/72-collection-base-routes.spec.ts
```

**Settings → settings.spec.ts**
```
tests/e2e/27-settings-general.spec.ts
tests/e2e/47-settings-wip-cleanup.spec.ts
```

**Fields & Blocks → fields.spec.ts**
```
tests/e2e/41-reference-fields.spec.ts
tests/e2e/42-dynamic-field-tdz.spec.ts
tests/e2e/53-block-media-persist.spec.ts
tests/e2e/53-object-layout.spec.ts
tests/e2e/83-json-field-viewer.spec.ts
tests/e2e/96-block-stable-ids.spec.ts
```

**Security → security.spec.ts**
```
tests/e2e/80-security-audit-document-model.spec.ts
tests/e2e/82-cors-auth-headers.spec.ts
tests/e2e/124-admin-template-xss.spec.ts
```

**Dashboard & Stats → dashboard.spec.ts**
```
tests/e2e/71-home-link-redirect.spec.ts
tests/e2e/97-stats-dashboard-fixes.spec.ts
tests/e2e/100-demo-login-stats.spec.ts
tests/e2e/119-admin-dashboard-fragments.spec.ts
tests/e2e/123-admin-page-weight.spec.ts
```

**Performance/Infra → infra.spec.ts**
```
tests/e2e/118-admin-background-request-load.spec.ts
tests/e2e/120-bootstrap-skip-latency.spec.ts
tests/e2e/126-runner-contracts.spec.ts
```

---

## Final File Structure

```
tests/e2e/
├── auth-ui.spec.ts              # UI login/logout flows
├── auth-api.spec.ts             # API auth (register, login, OTP, magic-link)
├── two-factor.spec.ts           # All 2FA tests
├── media-core.spec.ts           # Media library UI
├── media-upload.spec.ts         # Upload flows
├── media-api.spec.ts            # Media API tests
├── plugin-core.spec.ts          # Plugin system core
├── plugin-settings.spec.ts      # Plugin configuration
├── plugin-catalog.spec.ts       # Individual plugin tests
├── rbac.spec.ts                 # Roles and permissions
├── multi-tenant.spec.ts         # Multi-tenancy
├── content-crud.spec.ts         # Content CRUD
├── content-forms.spec.ts        # Content form UI
├── content-serialization.spec.ts # Nested data handling
├── forms.spec.ts                # Forms builder
├── cache.spec.ts                # Caching system
├── richtext.spec.ts             # All rich text editors
├── users.spec.ts                # User management
├── collections.spec.ts          # Collection/schema management
├── settings.spec.ts             # Settings pages
├── fields.spec.ts               # Field types and blocks
├── security.spec.ts             # Security features
├── dashboard.spec.ts            # Admin dashboard
├── infra.spec.ts                # Performance/infrastructure
├── smoke.spec.ts                # Entry smoke tests
├── 01-health.spec.ts            # Health checks
├── 03-admin-dashboard.spec.ts   # Keep (core)
├── 07-api.spec.ts               # Keep (core API)
├── 09-integration.spec.ts       # Keep (integration)
├── 13-migrations.spec.ts        # Keep
├── 14-database-tools.spec.ts    # Keep
├── 100-graphql.spec.ts          # Keep
├── 94-self-host-smoke.spec.ts   # Keep
├── 96-mcp-endpoint.spec.ts      # Keep
└── fixtures/
    ├── auth-fixtures.ts
    ├── media-fixtures.ts
    ├── plugin-fixtures.ts
    └── content-fixtures.ts
```

**Final count: ~35-40 spec files** (down from 149)

---

## Execution Order

1. **Phase 1-2** (Auth + 2FA): Low risk, clear boundaries — start here
2. **Phase 7-8** (Cache + Richtext): Small, isolated merges
3. **Phase 3** (Media): Medium complexity, many files
4. **Phase 6** (Content): Medium complexity
5. **Phase 4** (Plugins): High file count, needs careful attention
6. **Phase 5** (RBAC/Tenant): State-dependent, run last
7. **Phase 9** (Cleanup): Final minor merges

---

## Verification Checklist

After each phase:

1. Run the consolidated file: `pnpm test:e2e <new-file>.spec.ts`
2. Run full suite: `pnpm test:e2e`
3. Check CI passes
4. Delete old files only after verification
5. Commit with message: `test(e2e): consolidate <category> tests (X files → Y)`

---

## Notes for Executor

- **Do NOT delete tests** — only merge and reorganize
- **Preserve test names** — makes it easy to trace back to original files
- **Use `test.describe()` liberally** — keeps logical grouping clear
- **Share fixtures** — reduces setup duplication
- **Run tests frequently** — catch breakage early
- When in doubt, keep tests separate rather than risk losing coverage
