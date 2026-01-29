# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SonicJS is an edge-native headless CMS built on Cloudflare Workers with Hono.js and TypeScript. It uses a monorepo structure with npm workspaces.

## Monorepo Layout

- `packages/core/` — Main publishable package (`@sonicjs-cms/core`). Contains all CMS logic: routes, services, middleware, plugins, templates, DB schema.
- `packages/create-app/` — CLI scaffolding tool (`create-sonicjs`)
- `packages/templates/` — Template system package
- `my-sonicjs-app/` — Local development/test app that consumes `@sonicjs-cms/core`. Runs on Wrangler at `localhost:8787`.
- `www/` — Marketing/docs website (Next.js + MDX)
- `tests/` — E2E tests (Playwright)

## Common Commands

```bash
# Development
npm run dev                  # Start local dev server (my-sonicjs-app at :8787)
npm run build:core           # Build the core package (tsup)
npm run db:reset             # Reset local D1 database

# Unit tests (Vitest, run inside packages/core)
npm run test                 # Run all unit tests
npm run test:cov             # Run with coverage (90% threshold enforced)
npm run test:watch           # Watch mode

# E2E tests (Playwright, Chromium only, single worker)
npm run e2e                  # Full E2E suite (auto-starts dev server if needed)
npm run e2e:ui               # E2E with Playwright UI
npm run e2e:smoke            # Quick smoke test subset

# Run a single E2E test file
npx playwright test --config=tests/playwright.config.ts tests/e2e/01-health.spec.ts

# Run a single unit test file
npx vitest --run packages/core/src/services/cache.test.ts

# Type checking & linting
npm run type-check           # TypeScript noEmit check on core package
npm run lint                 # Same as type-check (aliased)
```

## Architecture

### Application Factory
`packages/core/src/app.ts` exports `createSonicJSApp(config)` which assembles the full Hono application:
- Registers middleware stack (bootstrap, auth, metrics)
- Mounts all route modules
- Initializes plugins (email, OTP, AI search, cache, etc.)
- Configures Cloudflare bindings (D1, KV, R2, AI, Vectorize)

### Cloudflare Bindings (env)
The app expects these Cloudflare bindings defined in `wrangler.toml`:
- `DB` — D1 database (SQLite at edge)
- `CACHE_KV` — KV namespace for caching
- `MEDIA_BUCKET` — R2 bucket for file storage
- `AI` — Workers AI (for embeddings)
- `VECTORIZE_INDEX` — Vectorize index (for semantic search)

### Database
- **ORM**: Drizzle ORM with D1 (SQLite)
- **Schema**: `packages/core/src/db/schema.ts` — defines tables: `users`, `collections`, `content`, `contentVersions`, `media`, `apiTokens`, `plugins`, `systemLogs`, `workflowHistory`
- **Migrations**: SQL files in `packages/core/migrations/` (numbered `NNN_description.sql`). A prebuild script generates `migrations-bundle.ts`.

### Route Organization
Routes in `packages/core/src/routes/` are domain-separated:
- `api.ts`, `api-content-crud.ts`, `api-media.ts`, `api-system.ts` — Public/content API
- `auth.ts` — Login, register, logout
- `admin-*.ts` — Admin UI pages (dashboard, content, media, users, collections, plugins, settings, forms, logs)

### Plugin System
Plugins live in `packages/core/src/plugins/`:
- `core-plugins/` — Built-in plugins (AI search, email, OTP login, database tools, seed data, turnstile, workflow, analytics)
- `available/` — Optional plugins (magic link auth)
- `sdk/` — Plugin SDK for building plugins
- Plugins use `PluginBuilder` pattern: define metadata, routes, menu items, lifecycle hooks, then `.build()`

### Template System
Admin UI is server-rendered HTML using template functions in `packages/core/src/templates/`:
- `pages/` — Full admin pages (`admin-*.template.ts`)
- `components/` — Reusable UI components
- `layouts/` — Page layouts (`admin-layout-v2.template.ts`)
- Frontend interactivity via HTMX
- Glass morphism design system: `backdrop-blur-md bg-black/20`, `border border-white/10`, `shadow-xl`, `rounded-xl`, `space-y-6`

### Services Layer
`packages/core/src/services/` contains business logic:
- `collection-loader.ts` / `collection-sync.ts` — Dynamic collection management
- `auth-validation.ts` — Registration/login validation
- `cache.ts` — KV-based caching
- `plugin-service.ts` / `plugin-bootstrap.ts` — Plugin lifecycle
- `settings.ts` — System config persistence
- `logger.ts` — Structured logging
- `migrations.ts` — DB migration runner

### Build System
Core package uses `tsup` with multiple entry points (`index`, `services`, `middleware`, `routes`, `templates`, `plugins`, `utils`, `types`). Outputs dual ESM + CJS. External: `hono`, `drizzle-orm`, `zod`, `@cloudflare/workers-types`. Bundled: `drizzle-zod`, `marked`, `highlight.js`, `semver`.

## Testing Details

- **Unit tests**: Vitest with `v8` coverage. Tests co-located as `*.test.ts` in `packages/core/src/`. Coverage excludes templates, routes, plugins, and scripts.
- **E2E tests**: Playwright (Chromium only). Tests in `tests/e2e/` numbered sequentially (e.g., `01-health.spec.ts`, `05-content.spec.ts`). Uses single worker to avoid D1 conflicts. Auto-starts dev server when `BASE_URL` is not set.
- **CI**: GitHub Actions (`.github/workflows/pr-tests.yml`) runs type-check, unit tests with coverage, build, deploys preview to Cloudflare, then runs E2E against the preview URL.

## Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Collections | snake_case | `blog_posts` |
| Schema fields | camelCase | `firstName` |
| DB columns | snake_case | `first_name` |
| API responses | camelCase | `userId` |
| Functions/variables | camelCase | `getUserById` |
| Classes/Types/Interfaces | PascalCase | `UserService` |
| Constants | SCREAMING_SNAKE_CASE | `MAX_RETRIES` |
| File names | kebab-case | `user-service.ts` |

## Key Principles

- **Edge-first**: All code runs on Cloudflare Workers globally
- **TypeScript-first**: Strict typing throughout
- **Simplicity**: Minimal, targeted changes; avoid complex refactoring
- **Plan first**: Read the codebase, understand the problem, write a plan before implementing
