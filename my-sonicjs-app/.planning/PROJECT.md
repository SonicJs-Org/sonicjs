# SonicJS Redirect Plugin

## What This Is

A redirect management plugin for SonicJS that handles URL redirects with exact matching, sub-millisecond caching, and provides a foundation for other plugins like QR code generation to build upon. Redirects are managed as a content type with a full admin UI, CSV import/export, programmatic API access, hit tracking, and audit trail.

## Current State

**Shipped:** v1.0 (2026-02-01)

**Codebase:**
- 13 TypeScript files, 4,489 lines
- 3 database migrations (032, 033, 034)
- Full plugin with routes, services, templates, middleware, utilities

**Capabilities:**
- ✓ Create, edit, delete redirects via admin UI
- ✓ Search, filter, sort redirect list
- ✓ CSV import/export with validation
- ✓ REST API with RFC 9457 errors
- ✓ Hit count tracking (async, non-blocking)
- ✓ Audit trail (created by, updated by)
- ✓ LRU cache for sub-millisecond lookups
- ✓ Circular redirect detection
- ✓ HTTP status codes: 301, 302, 307, 308, 410

## Core Value

Reliable, performant URL redirection that preserves SEO value during site migrations while providing a flexible foundation for dynamic URL management features like QR code tracking.

## Requirements

### Validated

- ✓ Plugin architecture with lifecycle management — v1.0
- ✓ Redirect CRUD operations (create, read, update, delete) — v1.0
- ✓ Admin UI with search, filter, sort, delete confirmation — v1.0
- ✓ CSV import/export for bulk operations — v1.0
- ✓ REST API for programmatic access — v1.0
- ✓ Hit count tracking per redirect — v1.0
- ✓ Audit trail (created by, updated by, timestamps) — v1.0
- ✓ Circular redirect detection — v1.0
- ✓ URL normalization for consistent matching — v1.0
- ✓ LRU caching for performance — v1.0
- ✓ HTTP status codes 301/302/307/308/410 — v1.0

### Active

(For next milestone — v2.0)

- [ ] Cloudflare bulk redirect integration for edge-level redirects
- [ ] Regex pattern matching for complex URL transformations
- [ ] 404 detection and suggested redirects
- [ ] Redirect preview/testing interface

### Out of Scope

- Advanced analytics (timestamp, referrer, user agent) — future analytics plugin
- A/B testing redirects — use dedicated tools
- User-level redirect rules — caching complexity
- Historical redirect versioning — use git for CSV exports

## Context

**Technical Environment:**
- TypeScript with strict type checking
- Hono web framework for routing
- D1 SQLite database with direct SQL queries
- Cloudflare Workers edge runtime
- HTMX for admin UI interactions
- tiny-lru for in-memory caching

**Integration Points:**
- Plugin system via PluginBuilder
- Middleware mounted early (before routing)
- API at /api/redirects
- Admin UI at /admin/redirects

## Constraints

- **Runtime**: Cloudflare Workers edge environment — must be fast, no blocking operations
- **Database**: D1 SQLite — query performance critical for redirect lookup
- **Architecture**: Must follow SonicJS plugin patterns
- **Performance**: Redirect lookup must be highly optimized — users expect instant redirects

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Use MatchType enum (0=exact, 1=partial, 2=regex) | Database efficiency via INTEGER storage | ✓ Good |
| 1000 entry LRU cache default | Balance memory usage with cache coverage | ✓ Good |
| Visited-set algorithm for circular detection | Efficient O(n) traversal | ✓ Good |
| All-or-nothing CSV validation | Prevents partial imports | ✓ Good |
| RFC 9457 Problem Details for API errors | Standardized error format | ✓ Good |
| Async fire-and-forget hit tracking | Don't block redirect execution | ✓ Good |
| LEFT JOINs for analytics/audit display | Single query for all data | ✓ Good |
| Follow contact-form plugin patterns | Ensures consistency | ✓ Good |

---
*Last updated: 2026-02-01 after v1.0 milestone*
