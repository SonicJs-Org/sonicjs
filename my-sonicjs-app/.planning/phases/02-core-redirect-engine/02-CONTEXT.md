# Phase 2: Core Redirect Engine - Context

**Gathered:** 2026-01-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Building the redirect execution system — URL matching logic, validation rules, middleware interception, caching strategy, and HTTP redirect responses. This phase delivers the runtime behavior: when a request comes in, the system checks for redirects, validates configurations, executes the redirect with the correct status code, and does all of this with sub-millisecond cache hits and under 10ms cache misses.

Admin UI, CSV operations, and API endpoints are separate phases.

</domain>

<decisions>
## Implementation Decisions

### URL Matching Behavior
- **Case sensitivity**: Case-insensitive matching (/Blog and /blog match the same redirect)
- **Trailing slashes**: Normalized — /page and /page/ are treated as the same URL (match either way)
- **Query parameter matching**: Configurable per redirect — admin chooses whether each redirect includes or ignores query parameters in matching
- **Query parameter preservation**: Configurable per redirect — admin chooses whether to preserve query params in destination URL (e.g., /old?ref=email → /new?ref=email vs /new)

### Validation & Error Handling
- **Circular redirect detection**: Both at save time AND runtime as safety net
  - Save time: Prevent admin from creating circular redirects (A→B→A blocked with error)
  - Runtime: Detect and break loops if they somehow exist (safety net)
- **Chain warning threshold**: 3 hops (A→B→C→D)
  - Warn admin when redirect chains reach 3 hops
  - Chains waste crawl budget and dilute link equity
- **Validation failure behavior**: Save but mark inactive
  - When validation fails (circular, invalid URL), save the redirect but automatically disable it
  - Show validation warning to admin
  - Admin can fix issues and re-enable
- **Destination URL validation**: Warn but allow
  - Check if destination URL exists (returns 200)
  - If destination is broken, show warning to admin
  - Still allow saving (admin might create the destination page later)

### Caching Strategy
- **Cache scope**: Frequently accessed redirects only (LRU cache with size limit)
- **Cache size limit**: 1000 redirects
  - Balance between memory usage and hit rate
  - Appropriate for medium-to-large sites
- **Cache invalidation**: On any redirect change
  - Clear entire cache when admin creates/updates/deletes any redirect
  - Simple invalidation strategy ensures consistency
- **Cache warming**: Pre-warm on startup
  - Load popular redirects into cache when Worker starts
  - First requests benefit from warm cache

### Redirect Execution Flow
- **Middleware priority**: High priority (5)
  - Execute after auth/security plugins but before content plugins
  - Ensures redirects catch URLs early in request lifecycle
- **Performance logging & analytics**: User configurable
  - **Plugin-level setting**: Enable/disable enhanced analytics globally (affects all redirects)
  - **Per-redirect setting**: Enable enhanced analytics for specific redirects
  - **Baseline**: Hit count collected for all redirects (always on)
  - Enhanced analytics may include: lookup time, cache hit/miss, source details
- **Inactive redirect handling**: No redirect, pass through
  - When redirect is marked inactive, URL processes normally as if no redirect exists
  - May 404 if underlying page doesn't exist (expected behavior)
- **410 (Gone) status handling**: Standard redirect behavior
  - Return 410 status with empty body
  - Same execution flow as other redirect status codes

### Claude's Discretion
- Exact cache eviction algorithm (LRU implementation details)
- Performance thresholds for slow redirect warnings
- Circular redirect runtime detection implementation (hop limit)
- URL normalization edge cases (encoding, special characters)

</decisions>

<specifics>
## Specific Ideas

- Hit count is baseline analytics for all redirects (foundation for Phase 6)
- Enhanced analytics opt-in at two levels (plugin-wide and per-redirect) provides flexibility
- Pre-warming cache on startup aligns with Cloudflare Workers initialization patterns

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 02-core-redirect-engine*
*Context gathered: 2026-01-30*
