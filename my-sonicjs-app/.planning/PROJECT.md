# SonicJS Redirect Plugin

## What This Is

A redirect management plugin for SonicJS that handles URL redirects with multiple match types (exact, partial, regex), integrates with Cloudflare bulk redirects for performance, and provides a foundation for other plugins like QR code generation to build upon. Redirects are managed as a content type with a full admin UI, CSV import/export, and programmatic API access.

## Core Value

Reliable, performant URL redirection that preserves SEO value during site migrations while providing a flexible foundation for dynamic URL management features like QR code tracking.

## Requirements

### Validated

(Existing SonicJS capabilities the plugin will build upon)

- ✓ Plugin architecture with lifecycle management — existing
- ✓ Collection-based content types with declarative schemas — existing
- ✓ Admin UI with CRUD operations — existing
- ✓ D1 database with Drizzle ORM — existing
- ✓ Cloudflare Workers edge runtime — existing
- ✓ API endpoint generation for collections — existing
- ✓ Middleware pipeline for request processing — existing
- ✓ Authentication and user tracking — existing

### Active

(New capabilities this plugin will deliver)

- [ ] Redirect content type with source pattern, destination URL, match type, HTTP status code
- [ ] Match type support: exact, partial, regex with priority (exact > partial > regex)
- [ ] HTTP status code support: 301, 302, 307, 308, 410
- [ ] Active/inactive toggle for redirects
- [ ] Basic analytics: hit count tracking per redirect
- [ ] Audit trail: last updated timestamp and user
- [ ] Admin menu link to redirect management
- [ ] List view with search and filter capabilities
- [ ] CSV export of all redirects
- [ ] CSV import for bulk redirect operations
- [ ] API endpoints for programmatic redirect creation (for QR plugin and others)
- [ ] Automatic Cloudflare bulk redirect offloading for simple redirects (exact/partial match)
- [ ] Local execution for complex redirects (regex patterns)
- [ ] Validation to prevent circular redirects
- [ ] High-performance caching for redirect lookup
- [ ] Manual testing interface for redirect verification

### Out of Scope

- Advanced analytics (timestamp, referrer, user agent) — deferred to future analytics plugin that can hook into redirect events
- Real-time redirect statistics dashboard — basic hit count is sufficient for v1
- A/B testing or conditional redirects — not needed for core use case
- Import from other redirect systems — CSV import covers bulk operations

## Context

**Existing Codebase:**
- Brownfield SonicJS application with established plugin patterns
- contact-form plugin serves as architectural reference
- Plugin system supports routes, services, components, and lifecycle hooks
- Collections automatically generate admin UI and API endpoints
- Cloudflare Workers edge runtime for global performance

**Key Use Cases:**
1. **SEO Migrations:** Preserve link equity when restructuring URLs or migrating content
2. **Page Maintenance:** Manage broken links and URL changes over time
3. **QR Code Foundation:** Short URLs that redirect to destinations, enabling:
   - Usage tracking (via hit counts)
   - Dynamic destinations (change target without reprinting QR code)
   - Future extensibility for other dynamic URL features

**Technical Environment:**
- TypeScript with strict type checking
- Hono web framework for routing
- Drizzle ORM for database access
- D1 SQLite database
- Cloudflare R2, KV, and bulk redirect APIs available

## Constraints

- **Runtime**: Cloudflare Workers edge environment — must be fast, no blocking operations
- **Database**: D1 SQLite — query performance critical for redirect lookup
- **Architecture**: Must follow SonicJS plugin patterns from contact-form reference
- **Compatibility**: Must expose API that other plugins (QR code) can depend on
- **Performance**: Redirect lookup must be highly optimized with caching — users expect instant redirects
- **Cloudflare Integration**: Leverage Cloudflare bulk redirect API where possible to offload work from origin

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Store redirects as collection | Leverages existing admin UI, API generation, and content management patterns | — Pending |
| Match priority: exact > partial > regex | Predictable behavior prevents surprising matches | — Pending |
| Automatic Cloudflare offloading | Simple redirects (exact/partial) to Cloudflare, complex (regex) stay local for performance | — Pending |
| Basic analytics only (hit count) | Keep plugin focused; future analytics plugin can hook events for deeper metrics | — Pending |
| CSV import/export for bulk ops | Admins prefer spreadsheet editing over web forms for large-scale changes | — Pending |
| Active/inactive toggle | Allow temporary disable without deletion for testing and rollback | — Pending |

---
*Last updated: 2026-01-30 after initialization*
