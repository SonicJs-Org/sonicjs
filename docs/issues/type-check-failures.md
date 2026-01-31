# Type-check failures in `@sonicjs-cms/core`

## Summary
`npm run type-check` currently fails in the core workspace. The compiler reports 30+ errors across plugins, admin routes, and template helpers, so CI never reaches the build/test steps. This blocks any typed release of the CMS packages because `tsc --noEmit` is part of the publish pipeline.

## Reproduction
1. Run `npm run type-check` at the repo root (the script delegates to `@sonicjs-cms/core`).
2. TypeScript exits with code 2. The same behavior reproduces inside `packages/core`.

## Current progress
- Added Node + Workers globals to the `packages/core/tsconfig.json` (Cloudflare bindings + Node APIs such as `process`, `require`, `NodeJS` namespaces, etc.).
- Added explicit path mappings so the core package can resolve shared template modules without relying on the published build.
- Declared an ambient module for `posthog-node` so TelemetryService can type-check when the upstream package does not ship TypeScript defs.
- Removed the previous alias errors, so the compiler now reports the remaining logic-level issues that must be addressed in code.

## Outstanding compiler errors (abbreviated)
- **Plugin config** (`src/plugins/config/plugin-config.ts`): calls to `z.object` helpers are missing default values, so the generated schema functions now expect more arguments than provided.
- **Plugin registry exports** (`src/plugins/core-plugins/index.ts`): the registry file no longer exports `CORE_PLUGIN_IDS` / `PLUGIN_REGISTRY`. Downstream imports need to switch to the new `PluginRegistryImpl` API.
- **Media plugin + admin routes**: multiple `id`, `db`, and `mediaGridHTML` identifiers are used without prior declaration, indicating unfinished refactors in `src/plugins/core-plugins/media/index.ts` and `src/routes/admin-collections.ts` / `admin-media.ts`.
- **Workflow + SDK builder**: references to `_workflowSchemas`, `context`, `isAuthor`, and `basePath` were removed elsewhere but still consumed inside the workflow plugin and SDK builder services.
- **Validation gaps**: Zod parsing in `src/routes/auth.ts` produces `unknown` because its schema types are not inferred. Template helpers such as `admin-content-list` use implicit `any` parameters and undefined interfaces (e.g., `FilterBarData`).
- **Telemetry utilities** (`src/utils/telemetry-id.ts`): `context.projectName` is optional but dereferenced without narrowing, so TypeScript reports `Object is possibly 'undefined'`.

See the `npm run type-check` output in this workspace run (timestamped Feb 25, 2025) for the full 33-error log.

**Note:** The former OTP Login and Magic Link plugins were removed; magic link and email OTP are now provided via Better Auth plugins in app config (see [authentication.md](../authentication.md)). The "Email + OTP plugins" type-check category above no longer applies.

## Next steps
1. **Stabilize plugin/config schemas** – update the Zod builders so helper functions always receive the required arguments or provide defaults.
2. **Align with the new registry** – update imports to use the currently exported registry helpers and extend types where necessary.
3. **Clean up dangling identifiers** – audit the admin routes + media/plugin code paths to reintroduce the missing variables (`db`, `mediaGridHTML`, `basePath`, etc.) or remove unused logic.
4. **Tighten schemas** – explicitly type `validatedData`, define `FilterBarData`, and add concrete parameter types to template helpers.
5. **Add regression tests** – once `tsc` passes, add targeted unit specs under `packages/core/src/__tests__` plus a Playwright flow to verify plugin management still works end-to-end.

Tracking issue: https://github.com/lane711/sonicjs/issues/330
