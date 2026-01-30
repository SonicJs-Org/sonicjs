# Technology Stack

**Analysis Date:** 2026-01-30

## Languages

**Primary:**
- TypeScript 5.8.3 - All source code, strict type checking enabled
- JavaScript (runtime) - Cloudflare Workers environment

**Secondary:**
- SQL - SQLite database queries (via Drizzle ORM abstraction)
- HTML/CSS - Template rendering in `src/templates/`

## Runtime

**Environment:**
- Cloudflare Workers (Edge computing platform)
- Node.js >= 18.0.0 (development and tooling)
- Compatibility date: 2025-05-05 with nodejs_compat flag

**Package Manager:**
- npm (v10+)
- Lockfile: package-lock.json (committed)
- Monorepo structure: `my-sonicjs-app/` (consumer) and `packages/core/` (library)

## Frameworks

**Core:**
- Hono 4.11.7 - Web framework for Cloudflare Workers, routing and middleware
- Drizzle ORM 0.44.2+ - Database ORM for SQLite (D1) with type safety
- Zod 3.25.67+ - Schema validation and TypeScript type inference

**Testing:**
- Vitest 2.1.8 / 4.0.5 - Unit and integration test runner
- @vitest/coverage-v8 - Code coverage reporting

**Build/Dev:**
- Tsup 8.5.0 - TypeScript bundler for library compilation
- Wrangler 4.59.1 - Cloudflare Workers CLI for deployment and local dev
- TypeScript 5.8.3 / 5.9.3 - Compiler and type checking
- tsx - TypeScript script executor (for seed scripts)

## Key Dependencies

**Critical:**
- `@cloudflare/workers-types` 4.20250620.0 - Type definitions for Cloudflare bindings (D1, R2, KV, etc.)
- `drizzle-orm` 0.44.2+ - ORM core for database operations
- `drizzle-zod` 0.8.3 - Integration between Drizzle schemas and Zod for type-safe schema generation
- `hono` 4.11.7 - HTTP framework, routing, context/middleware handling

**Infrastructure:**
- `marked` 16.4.1 - Markdown parsing and HTML rendering (used in content templates)
- `highlight.js` 11.11.1 - Syntax highlighting for code blocks in content
- `semver` 7.7.3 - Version comparison and parsing utilities
- `glob` 10.5.0 - File pattern matching for plugin discovery

## Configuration

**Environment:**
- `.env` files not used; all config via `wrangler.toml`
- Environment variables set in `wrangler.toml` under `[vars]` section
- Secrets handled via Cloudflare Workers secrets (not in source)
- Development database uses local D1 instance via Wrangler

**Build:**
- `tsconfig.json` - TypeScript configuration with strict mode enabled
  - Target: ES2022
  - Module resolution: bundler
  - Path alias: `@/*` → `./src/*`
  - Type checking for Cloudflare Workers and Node.js
- `tsup.config.ts` - Entry points for library distribution
  - Outputs: ESM and CommonJS formats
  - External dependencies: hono, drizzle-orm, zod, @cloudflare/workers-types
  - Bundled dependencies: drizzle-zod, marked, highlight.js, semver
  - Tree-shaking enabled
- `vitest.config.ts` - Test runner configuration
  - Environment: node
  - Coverage provider: v8
  - Test file patterns: `**/*.{test,spec}.{js,ts}`

## Platform Requirements

**Development:**
- Node.js 18.0.0 or higher
- npm with package-lock.json
- Cloudflare account for D1, R2, KV, and Workers AI (optional features)
- Wrangler CLI configured with account_id

**Production:**
- Deployment target: Cloudflare Workers global edge network
- Database: Cloudflare D1 (SQLite)
- File storage: Cloudflare R2 (S3-compatible object storage)
- Caching: Cloudflare KV (distributed key-value store)
- Optional: Cloudflare AI (Workers AI for embeddings and search)
- Optional: Cloudflare Turnstile (bot protection)

## Database

**Type:** SQLite via Cloudflare D1

**Connection:**
- Binding: `DB` (exposed in Hono context as `c.env.DB`)
- ORM: Drizzle ORM
- Migrations: `migrations/` directory, auto-applied on worker startup

**Schema Location:** `packages/core/src/db/schema.ts`
- Users table - authentication and user management
- Collections table - dynamic content schema definitions
- Content table - actual content items
- ContentVersions table - version history tracking
- Media table - file metadata and R2 references
- ApiTokens table - programmatic API access
- WorkflowHistory table - content workflow tracking
- PluginSettings table - plugin configurations

## Storage & Caching

**File Storage:**
- Cloudflare R2 bucket (S3-compatible)
- Binding: `MEDIA_BUCKET`
- Bucket name: `sonicjs-ci-media` (CI environment)
- Accessible via `/files/*` endpoint with CDN caching

**Caching:**
- Cloudflare KV namespace
- Binding: `CACHE_KV`
- Used by cache plugin and content caching

**Optional Features:**
- Cloudflare Workers AI - for semantic search embeddings
- Cloudflare Vectorize - for vector search storage

---

*Stack analysis: 2026-01-30*
