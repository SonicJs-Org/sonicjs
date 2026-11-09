# E2E consolidation

The suite has 53 active specs and preserves all 756 tests from the 149-spec baseline
`0ee0006f1ae5bb6f8532a147bb0563f57a95d551`. Consolidation reduces files, not tests.
The original plan's smaller file estimate omitted 17 specs and understated several
groups. The verified layout contains 23 multi-source targets plus the renamed
single-source `auth-ui.spec.ts`: 24 renamed/merged targets and 29 unchanged standalones.
Counting by source multiplicity instead gives 23 multi-source and 30 single-source
specs; both descriptions account for the same 53 active specs.

Each `Source: <original filename>` describe block preserves the original module's
hooks, state, configuration, serial boundaries, conditional skips and fixture factory.
Test names and original assertions are preserved. The plugin activity regression has
one additional checked install prerequisite after inspecting the initial detail page, because
file consolidation removed its implicit dependency on earlier installation tests.
Installation runs only for an uninstalled plugin; installed active/inactive states retain
their original toggle branch and final state. The guard permits only that exact named
preparation and compares the remaining body
against the pinned original. The JSON viewer retains its extended factory;
tenant cleanup retains original IDs, admin flags and foreign-key deletion order.
Locks remain shared across files; test-scoped locks do not protect `beforeAll`.

Consolidation exposed local login rate-limit contention between API and UI files.
The shared fixture gives each local file one stable synthetic local client address,
including its hooks. The header applies only to same-origin Playwright API calls,
never browser or external CDN traffic. Local Miniflare accepts the synthetic
`CF-Connecting-IP`; a supplied `X-Forwarded-For` is insufficient because Miniflare
adds its own authoritative loopback client header. Requests within a file retain
the same real rate-limit bucket;
explicit client headers and remote targets keep their existing identities. This avoids
cross-file traffic consuming the cookie test's login budget, without changing limiter
thresholds, assertions, adding sleeps or retrying mutations. Focused Node checks cover
client isolation, same-file identity, explicit-header preservation and remote behavior.

`fixtures/auth-fixtures.ts` extracts the identical OTP/magic-link address helper.
The media, plugin and content fixture modules re-export the existing shared navigation,
activation/status and content-save helpers. These are used by multiple consolidated
sources and retain the original implementations and state, without duplicate wrappers.

`124-better-auth-upgrade.spec.ts` remains standalone because its four tests cover
non-2FA regressions. `126-runner-contracts.spec.ts` remains standalone so the infrastructure
config can run without an application, database or secrets. The cache plugin belongs
only to `cache.spec.ts`, despite appearing twice in the original plan.

The smoke config selects the original smoke filenames and only the former
`52-forms-smoke.spec.ts` scope inside `forms.spec.ts`: exactly 28 tests. It does not
select every forms test. Infrastructure selection remains exactly two runner contracts.

Public CDN stalls also caused two 30-second document navigation failures. Local
browser contexts now cache successful public vendor responses in worker memory,
using a worker-owned API client. The cache preserves real bytes, redirects, CORS
and content headers; unsuccessful responses stay unsuccessful. Pending downloads
remain context-scoped, while only completed responses cross contexts. Application
requests, remote targets, document readiness and explicit load timeouts remain native.
No assets or reports are committed, and downloads use zero retries.

## Preservation checks

```bash
node --test tests/e2e/consolidation/*.checks.mjs
node tests/e2e/consolidation/coverage-guard.mjs
node tests/e2e/consolidation/selection-guard.mjs
npm run type-check
npm test
npx playwright test --config=tests/playwright.infrastructure.config.ts --workers=2 --retries=0
npm run e2e -- --workers=2 --retries=0
```

Source validation reads pinned Git originals and checks the complete AST, imports,
validated helper extractions/re-exports and exact Source wrappers. Collection compares
full test multisets, including duplicate multiplicity, titles, suites, tags, timeouts,
expected status and annotation meaning. Selection checks compare the complete original
smoke and infrastructure test sets. Negative guard checks exercise assertion, skip,
lock, timeout, hook, factory, import, helper and wrapper tampering.

Use the disposable local database recipe in [the E2E guide](../../tests/e2e/README.md).
Build core first, apply local migrations to the same unique absolute persist directory,
and provide ignored local auth configuration. Existing fixtures seed admin/content;
no new seed data or remote resources are required. The final campaign runs with two
workers and zero retries; intermediate repeated full campaigns are batched for speed.
A cancelled intermediate cache campaign is recorded as cancelled, not passing.

## Verified source mapping

| Active spec | Original specs |
|---|---|
| `01-health.spec.ts` | `01-health.spec.ts` |
| `03-admin-dashboard.spec.ts` | `03-admin-dashboard.spec.ts` |
| `07-api.spec.ts` | `07-api.spec.ts` |
| `09-integration.spec.ts` | `09-integration.spec.ts` |
| `100-graphql.spec.ts` | `100-graphql.spec.ts` |
| `114-seed-admin-env-gate.spec.ts` | `114-seed-admin-env-gate.spec.ts` |
| `124-better-auth-upgrade.spec.ts` | `124-better-auth-upgrade.spec.ts` |
| `126-runner-contracts.spec.ts` | `126-runner-contracts.spec.ts` |
| `13-migrations.spec.ts` | `13-migrations.spec.ts` |
| `14-database-tools.spec.ts` | `14-database-tools.spec.ts` |
| `20-content-api-collection-filter.spec.ts` | `20-content-api-collection-filter.spec.ts` |
| `37-disable-registration.spec.ts` | `37-disable-registration.spec.ts` |
| `65-default-blog-post-seed.spec.ts` | `65-default-blog-post-seed.spec.ts` |
| `68-blog-post-validation-no-nesting.spec.ts` | `68-blog-post-validation-no-nesting.spec.ts` |
| `68-login-redirect.spec.ts` | `68-login-redirect.spec.ts` |
| `68-user-profile-document.spec.ts` | `68-user-profile-document.spec.ts` |
| `78-new-content-dropdown.spec.ts` | `78-new-content-dropdown.spec.ts` |
| `80-redirect-management.spec.ts` | `80-redirect-management.spec.ts` |
| `81-versioning-optional.spec.ts` | `81-versioning-optional.spec.ts` |
| `86-api-key-auth.spec.ts` | `86-api-key-auth.spec.ts` |
| `87-session-lifecycle.spec.ts` | `87-session-lifecycle.spec.ts` |
| `91-database-table-search.spec.ts` | `91-database-table-search.spec.ts` |
| `92-api-keys-copy-before-redirect.spec.ts` | `92-api-keys-copy-before-redirect.spec.ts` |
| `94-content-edit-info-sidebar.spec.ts` | `94-content-edit-info-sidebar.spec.ts` |
| `94-self-host-smoke.spec.ts` | `94-self-host-smoke.spec.ts` |
| `95-mcp-admin.spec.ts` | `95-mcp-admin.spec.ts` |
| `96-mcp-endpoint.spec.ts` | `96-mcp-endpoint.spec.ts` |
| `97-otp-request-route.spec.ts` | `97-otp-request-route.spec.ts` |
| `auth-api.spec.ts` | `02b-authentication-api.spec.ts`, `02c-otp-login.spec.ts`, `02d-magic-link-auth.spec.ts`, `66-auth-better-auth.spec.ts`, `83-login-returns-token.spec.ts` |
| `auth-ui.spec.ts` | `02-authentication.spec.ts` |
| `cache.spec.ts` | `43-cache-plugin.spec.ts`, `80-cache-warming-documents.spec.ts`, `81-cache-collection-settings.spec.ts`, `97-cache-invalidation.spec.ts` |
| `collections.spec.ts` | `33-field-type-editor-options.spec.ts`, `34-field-type-persistence.spec.ts`, `35-collection-field-type-badges.spec.ts`, `36-collection-field-easymdx-edit.spec.ts`, `70-collection-registry.spec.ts`, `72-collection-base-routes.spec.ts` |
| `content-crud.spec.ts` | `05-content.spec.ts`, `100-content-title-preserved-on-edit.spec.ts`, `125-content-delete-confirmation-page.spec.ts`, `23-content-api-crud.spec.ts`, `26-content-duplicate.spec.ts`, `42-content-deletion-bug.spec.ts`, `62-public-content-api-status-visibility.spec.ts`, `63-document-blog-crud.spec.ts` |
| `content-forms.spec.ts` | `117-content-form-no-htmx.spec.ts`, `118-content-save-and-close.spec.ts`, `122-content-form-no-background-write.spec.ts`, `19-content-media-selector.spec.ts`, `39-slug-generation.spec.ts`, `54-hero-cta-style-persistence.spec.ts`, `55-collapsible-state-persistence.spec.ts`, `56-collapsible-validation-visibility.spec.ts` |
| `content-serialization.spec.ts` | `57-nested-array-serialization-scope.spec.ts`, `58-nested-object-serialization.spec.ts`, `59-array-media-picker-targeting.spec.ts` |
| `dashboard.spec.ts` | `100-demo-login-stats.spec.ts`, `119-admin-dashboard-fragments.spec.ts`, `123-admin-page-weight.spec.ts`, `71-home-link-redirect.spec.ts`, `97-stats-dashboard-fixes.spec.ts` |
| `fields.spec.ts` | `41-reference-fields.spec.ts`, `42-dynamic-field-tdz.spec.ts`, `53-block-media-persist.spec.ts`, `53-object-layout.spec.ts`, `83-json-field-viewer.spec.ts`, `96-block-stable-ids.spec.ts` |
| `forms.spec.ts` | `50-forms.spec.ts`, `51-turnstile-integration.spec.ts`, `52-forms-smoke.spec.ts`, `53-forms-as-content.spec.ts` |
| `infra.spec.ts` | `118-admin-background-request-load.spec.ts`, `120-bootstrap-skip-latency.spec.ts` |
| `media-api.spec.ts` | `81-media-document-model.spec.ts`, `92-media-create-folder.spec.ts` |
| `media-core.spec.ts` | `06-media.spec.ts`, `09-media-bulk-actions.spec.ts`, `10-media-view-switching.spec.ts`, `18-media-bulk-menu-zindex.spec.ts`, `25-media-cleanup-unused.spec.ts`, `88-media-library-fixes.spec.ts` |
| `media-upload.spec.ts` | `17-media-upload-immediate.spec.ts`, `24-media-thumbnail-loading.spec.ts`, `91-media-upload-date.spec.ts` |
| `multi-tenant.spec.ts` | `70-multi-tenant.spec.ts`, `71-tenant-membership-gate.spec.ts`, `72-per-tenant-roles.spec.ts`, `73-tenant-members.spec.ts`, `74-tenant-invitations.spec.ts`, `75-global-document-types.spec.ts`, `76-user-tenant-memberships.spec.ts` |
| `plugin-catalog.spec.ts` | `38-turnstile-plugin.spec.ts`, `39-ai-search-plugin.spec.ts`, `68-plugin-activity-log.spec.ts`, `76-plugin-menu-singleton.spec.ts`, `89-hello-cruel-world-plugin.spec.ts` |
| `plugin-core.spec.ts` | `121-plugin-card-display-names.spec.ts`, `15-plugins.spec.ts`, `21-plugin-version-display.spec.ts`, `28-plugin-filters-search.spec.ts`, `68-plugin-install-click.spec.ts`, `69-plugins-nav-accordion.spec.ts`, `79-plugin-filter-url.spec.ts`, `88-plugin-system.spec.ts`, `93-disabled-plugin-sidebar.spec.ts`, `94-removed-plugin-deactivated.spec.ts` |
| `plugin-settings.spec.ts` | `29-email-plugin-settings.spec.ts`, `68-example-plugin-settings.spec.ts`, `77-schema-driven-settings.spec.ts`, `90-plugin-stale-settings-pruning.spec.ts`, `91-plugin-routes-tab-persistence.spec.ts`, `93-oauth-providers-settings.spec.ts` |
| `rbac.spec.ts` | `67-rbac.spec.ts`, `70-rbac-roles-verbs.spec.ts`, `81-admin-rbac-access.spec.ts`, `85-admin-panel-roles-naming.spec.ts`, `95-viewer-sidebar-scope.spec.ts`, `97-user-edit-dynamic-roles.spec.ts`, `98-public-role-api-acl.spec.ts`, `99-rbac-grant-api-access.spec.ts` |
| `richtext.spec.ts` | `30-richtext-tinymce.spec.ts`, `31-richtext-quill.spec.ts`, `32-mdxeditor-new-content.spec.ts`, `32-mdxeditor-richtext.spec.ts`, `36-easymde-plugin-visible.spec.ts`, `77-lexical-editor.spec.ts` |
| `security.spec.ts` | `124-admin-template-xss.spec.ts`, `80-security-audit-document-model.spec.ts`, `82-cors-auth-headers.spec.ts` |
| `settings.spec.ts` | `27-settings-general.spec.ts`, `47-settings-wip-cleanup.spec.ts` |
| `smoke.spec.ts` | `smoke.spec.ts` |
| `two-factor.spec.ts` | `106-two-factor-auth.spec.ts`, `107-two-factor-admin-reset.spec.ts`, `108-two-factor-api-enforcement.spec.ts` |
| `users.spec.ts` | `115-admin-set-password.spec.ts`, `116-register-credential.spec.ts`, `15-user-xss-prevention.spec.ts`, `16-user-management.spec.ts`, `27-profile-picture-upload.spec.ts`, `78-author-user-search.spec.ts`, `80-user-profile-code-config.spec.ts` |

## Local acceptance — 2026-11-05

- Full suite: 748 passed, 8 original skips, zero failures/flaky; 756 collected, two workers, zero retries.
- Typecheck passed; units: 2068 passed, 247 skipped.
- Node preservation/harness checks: 41 passed; smoke membership: 28; serverless runner contracts: 2 passed.
- Runtime skipped identities match the original baseline exactly. Source hashes match the validated campaign.
- Earlier cancelled/interrupted/failed campaigns remain separate from the accepted result. Reports, disposable databases and credentials are kept outside the repository.
