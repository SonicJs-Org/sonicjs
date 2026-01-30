# Technology Stack

**Analysis Date:** 2026-01-30

## Languages

**Primary:**
- TypeScript 5.8.3+ - Full application codebase including server, plugins, schemas, routes
- HTML/CSS - Admin UI templates rendered server-side via Hono
- JavaScript (ES2022) - Build output and runtime execution

**Secondary:**
- SQL - SQLite via Drizzle ORM for database queries (`packages/core/src/db/schema.ts`)
- TOML - Wrangler configuration (`wrangler.toml`)

## Runtime

**Environment:**
- Node.js 18+ (specified in `package.json` engines field)
- Cloudflare Workers (edge runtime) - Primary deployment target
- Hono.js handles HTTP requests at Workers edge

**Package Manager:**
- npm 10.9.4+ (specified in volta config at workspace root)
- Lockfile: `package-lock.json` present (monorepo with npm workspaces)

## Frameworks

**Core:**
- **Hono 4.11.7** - Lightweight web framework for Cloudflare Workers, used as main HTTP router in `src/index.ts` and `packages/core/src/app.ts`
- **@sonicjs-cms/core 2.7.0** - Internal headless CMS framework (file-based dependency in `my-sonicjs-app/package.json`)

**Database/ORM:**
- **Drizzle ORM 0.44.2** - TypeScript-first ORM for D1 database access (`packages/core/src/db/schema.ts`)
- **Drizzle-Kit 0.30.0** - Schema management and migrations (`src/db/migrations-bundle.ts`)
- **Drizzle-Zod 0.8.3** - Schema validation integration (bundled in core build)

**Validation:**
- **Zod 3.25.67** - Runtime schema validation for request/response bodies and configuration

**Markdown/Content:**
- **Marked 16.4.1** - Markdown parsing (bundled in core, used for content rendering)
- **highlight.js 11.11.1** - Syntax highlighting for code blocks in markdown content

**Build/Dev:**
- **Wrangler 4.59.1** - Cloudflare Workers CLI and dev server (`wrangler dev` for local development)
- **tsup 8.5.0** - TypeScript bundler for `@sonicjs-cms/core` package builds (`packages/core/tsup.config.ts`)

**Testing:**
- **Vitest 2.1.8** - Unit and integration tests (`vitest.config.ts`)
- **Playwright 1.53.1** - E2E testing (configured in `tests/playwright.config.ts`)

## Key Dependencies

**Critical:**
- **@cloudflare/workers-types 4.20250620.0** - TypeScript type definitions for Cloudflare Workers bindings (D1, KV, R2, Vectorize)
- **hono 4.11.7** - HTTP routing and middleware in `src/index.ts` and throughout the application
- **drizzle-orm 0.44.2** - Database access layer for all data persistence
- **zod 3.25.67** - Runtime validation for plugins, collections, and API requests

**Infrastructure:**
- **semver 7.7.3** - Version parsing and comparison for plugin compatibility checks (`packages/core/src/plugins`)
- **glob 10.5.0** - File pattern matching for migrations and plugin discovery
- **tsx 4.20.3** - TypeScript executor for scripts (seed data, database setup)

## Configuration

**Environment:**
- **Wrangler configuration:** `wrangler.toml` in app root
  - Cloudflare account_id: `f9d6328dc3115e621758a741dda3d5c4`
  - D1 Database binding: `DB` (sonicjs-worktree-lane711-otp-email-branding)
  - R2 Bucket binding: `MEDIA_BUCKET` (sonicjs-ci-media)
  - KV Cache binding: `CACHE_KV` (a16f8246fc294d809c90b0fb2df6d363)
  - Environment variable: `ENVIRONMENT = "development"`
  - Observability: enabled

- **TypeScript configuration:** `tsconfig.json`
  - Target: ES2022
  - Module resolution: bundler
  - Strict mode enabled with exact optional property types
  - Path alias: `@/*` → `./src/*`
  - Types from `@cloudflare/workers-types` and `@types/node`

- **Build system:** `tsup.config.ts` in core package
  - Multiple entry points: index, services, middleware, routes, templates, plugins, utils, types
  - Output formats: ESM and CommonJS
  - External: `@cloudflare/workers-types`, `hono`, `drizzle-orm`, `zod` (not bundled)
  - Bundled: `drizzle-zod`, `marked`, `highlight.js`, `semver`

## Platform Requirements

**Development:**
- Node.js 18 or higher
- Cloudflare account (free tier supported)
- Wrangler CLI (npm installed)
- Local SQLite database for migrations

**Production:**
- Cloudflare Workers edge runtime (deployable via `npm run deploy`)
- Cloudflare D1 (SQLite database service)
- Cloudflare R2 (object storage for media)
- Cloudflare KV (key-value cache for performance)
- Cloudflare Vectorize (optional, for AI search semantic indexing)
- Cloudflare Workers AI (optional, for embedding generation)

---

*Stack analysis: 2026-01-30*
