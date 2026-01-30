# Technology Stack

**Project:** SonicJS Redirect Plugin
**Researched:** 2026-01-30
**Confidence:** HIGH

## Recommended Stack

### Core Technologies (Already in SonicJS)

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| TypeScript | ^5.9.3 | Type safety | Already in SonicJS stack, provides compile-time safety for redirect rules |
| Hono | ^4.11.7 | Web framework | Already in SonicJS, uses RegExpRouter (fastest JavaScript router) for redirect matching |
| Drizzle ORM | ^0.44.7 | Database ORM | Already in SonicJS, full D1 support with type-safe queries |
| Cloudflare D1 | Latest | SQLite database | Already in SonicJS, stores redirect rules as content type |
| Cloudflare Workers | Latest | Edge runtime | Already in SonicJS, executes at edge with <10ms global latency |

### New Dependencies for Redirect Plugin

| Library | Version | Purpose | Why Recommended |
|---------|---------|---------|-----------------|
| cloudflare | ^5.2.0 | Cloudflare API SDK | Official TypeScript SDK for Bulk Redirect API integration, actively maintained (published Dec 2025) |
| papaparse | ^5.5.3 | CSV parsing | Most popular CSV parser (4.7M weekly downloads), supports streaming, works in Workers, actively maintained (updated May 2025) |
| @types/papaparse | ^5.5.2 | TypeScript types for PapaParse | Official type definitions, recently updated (Jan 2026) |

### Optional Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| csv-parse | ^6.1.0 | Alternative CSV parser | If PapaParse has issues, this is the Node.js standard (part of csv project, 2676 dependents) |
| zod | ^4.1.12 (already in stack) | Schema validation | Validate CSV import data and redirect rule structure before saving |

### Infrastructure Components

| Component | Purpose | Notes |
|-----------|---------|-------|
| URLPattern API | URL pattern matching | Native to Cloudflare Workers (since March 2022), zero dependencies, path-to-regexp syntax |
| Cloudflare Bulk Redirect API | High-performance redirects | Runs before Worker execution, handles thousands of static redirects at edge |
| Cloudflare KV | Optional caching layer | For hot redirect lookups (500µs-10ms), consider if D1 latency becomes an issue |

## Installation

```bash
# New dependencies for redirect plugin
npm install cloudflare papaparse

# TypeScript types
npm install -D @types/papaparse

# Optional (already have zod)
# npm install zod
```

## Alternatives Considered

| Category | Recommended | Alternative | Why Not Alternative |
|----------|-------------|-------------|---------------------|
| CSV Parser | papaparse | csv-parse | PapaParse has better streaming support and 4.7M weekly downloads vs csv-parse. Works in both browser and Workers. |
| CSV Parser | papaparse | streaming-csv-worker | streaming-csv-worker is not published to npm, exists only as GitHub project. PapaParse is battle-tested. |
| URL Matching | URLPattern API | path-to-regexp | URLPattern is native to Workers (zero bundle size), based on path-to-regexp syntax anyway. |
| URL Matching | URLPattern API | Custom regex | URLPattern provides safer, more maintainable pattern matching. Use raw regex only for advanced cases. |
| API Client | cloudflare SDK | fetch API | Official SDK provides type safety and handles auth/pagination. Don't hand-roll API client. |
| Redirect Storage | D1 + Bulk Redirect API | KV only | D1 provides relational queries for admin UI. Bulk Redirects API for high-performance execution. Hybrid approach. |
| Redirect Storage | D1 + Bulk Redirect API | Worker code only | Bulk Redirects run before Worker (faster), handle static redirects. Worker handles dynamic/regex redirects. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| csv-stream or node-csv | Node.js specific, uses Node streams not WHATWG Streams | papaparse with WHATWG Streams API |
| @cfworker/csv | Returns 403 on npm page, appears unmaintained or private | papaparse |
| node-cloudflare SDK | Deprecated, points to cloudflare-typescript | cloudflare (official TypeScript SDK) |
| Complex regex for all redirects | Slow, error-prone, hard to maintain | URLPattern API for patterns, exact match for simple redirects |
| In-memory redirect cache | Workers have 128MB limit, instance-specific cache | D1 for storage, Cloudflare Bulk Redirects API for performance |
| Client-side redirects (meta refresh, JavaScript) | Bad for SEO, slow, crawlers may not follow | HTTP 301/302 redirects via Worker/Bulk Redirect API |

## Stack Patterns by Use Case

**Static Redirects (exact match, no wildcards):**
- Store in D1 via plugin admin UI
- Sync to Cloudflare Bulk Redirect API for edge execution
- Bulk API runs before Worker (fastest possible redirect)
- Limitation: No regex, no string replacement

**Dynamic Redirects (partial match, wildcards):**
- Store in D1 with URLPattern syntax patterns
- Worker middleware checks D1 on each request
- Use URLPattern.exec() for matching and parameter extraction
- Performance: D1 query adds 10-200ms depending on region

**Regex Redirects (complex patterns):**
- Store in D1 with regex patterns
- Worker middleware compiles regex once (cached)
- Use non-capturing groups `(?:...)` for performance
- Performance: Regex matching adds minimal overhead (<1ms)

**Hot Redirects (high traffic):**
- If D1 latency becomes issue, add KV layer
- KV caches frequently accessed redirects
- 500µs-10ms read latency for hot keys
- Cloudflare announced 3x faster KV reads (Oct 2025)

## Performance Characteristics

### Redirect Lookup Performance

| Approach | Latency | Best For |
|----------|---------|----------|
| Bulk Redirect API | <1ms | Static redirects, runs at edge before Worker |
| D1 exact match with index | 10-50ms | Dynamic redirects, relational queries |
| D1 regex scan | 50-200ms | Complex patterns, fewer than 10K rules |
| KV cached lookup | 0.5-10ms | Hot redirect paths, read-heavy workload |
| URLPattern matching | <1ms | Pattern matching logic in Worker |

### CSV Import Performance

| File Size | Memory | Parse Time | Notes |
|-----------|--------|------------|-------|
| <1MB | ~2MB | <100ms | In-memory parse with PapaParse |
| 1-10MB | ~20MB | 1-5s | Streaming parse recommended |
| 10-100MB | <128MB | 10-60s | Must use streaming, Workers 128MB limit |
| >100MB | N/A | N/A | Split file or process in Durable Object |

## Version Compatibility

| Package | Version | Compatible With | Notes |
|---------|---------|-----------------|-------|
| cloudflare | ^5.2.0 | TypeScript >= 4.5, Node 18+ | Published Dec 2025, actively maintained |
| papaparse | ^5.5.3 | Any runtime with WHATWG Streams | Last updated May 2025, 4.7M weekly downloads |
| drizzle-orm | ^0.44.7 | D1, TypeScript 5.9.3 | Already in stack, supports latest D1 features |
| hono | ^4.11.7 | Cloudflare Workers, TypeScript | Already in stack, RegExpRouter is fastest |
| @types/papaparse | ^5.5.2 | papaparse ^5.5.3 | Updated Jan 2026 |

## Cloudflare Bulk Redirect API Integration

### API Structure

**Three components:**
1. **URL Redirects** - Simple objects with source URL, target URL, status code
2. **Bulk Redirect Lists** - Lists containing URL redirects
3. **Bulk Redirect Rules** - Rules that enable lists (powered by Ruleset Engine)

### API Requirements

**Authentication:**
- Account Rulesets: Edit permission
- Account Filter Lists: Edit permission
- Use Cloudflare API token (not key)

**Workflow:**
1. Create Bulk Redirect List via API
2. Add URL redirect items to list
3. Create Bulk Redirect Rule to enable list

### Limitations

- **No regex support** - Bulk Redirects do not support regular expressions or string replacement
- **No wildcards** - Must use redirect parameters (subpath matching, subdomains, preserve query string)
- **Static only** - Essentially static configurations, not dynamic

**When to use Cloudflare Bulk Redirect API:**
- Hundreds to thousands of exact-match redirects
- Maximum performance required (runs before Worker)
- SEO migrations with exact URL mappings
- Simple hostname or path redirects

**When to use Worker code:**
- Regex patterns needed
- Dynamic target URL construction
- Complex matching logic
- Integration with CMS data (content-driven redirects)

## Regex Best Practices for TypeScript

### Performance Optimizations

1. **Compile once, reuse:** Compile regex patterns at module load, not per-request
2. **Use non-capturing groups:** `(?:...)` instead of `(...)` when capture not needed
3. **Keep patterns simple:** Break complex patterns into smaller checks
4. **Test thoroughly:** Use regex testers for visualization and debugging

### Code Patterns

```typescript
// Good: Compile once at module level
const REDIRECT_PATTERNS = {
  blog: /^\/blog\/(\d{4})\/(\d{2})\/(.+)$/,
  product: /^\/products?\/(?:category\/)?(.+)$/
} as const;

// Good: Non-capturing group for performance
const pattern = /^\/api\/(?:v1|v2)\/users$/;

// Bad: Compiling regex in hot path
app.get('*', (c) => {
  const match = new RegExp(pattern).exec(c.req.url); // Don't do this!
});
```

### Maintainability

- **Use named constants:** Make patterns readable and reusable
- **Comment complex patterns:** Explain intent for future maintainers
- **Handle null checks:** URLPattern.exec() and regex.exec() return null on no match

## Sources

**Cloudflare Documentation:**
- [Bulk Redirects - Cloudflare Rules docs](https://developers.cloudflare.com/rules/url-forwarding/bulk-redirects/)
- [Create Bulk Redirects via API](https://developers.cloudflare.com/rules/url-forwarding/bulk-redirects/create-api/)
- [JavaScript and web standards - Cloudflare Workers](https://developers.cloudflare.com/workers/runtime-apis/web-standards/)
- [Redirects - Cloudflare Workers examples](https://developers.cloudflare.com/workers/examples/redirect/)

**CSV Parsing:**
- [papaparse - npm](https://www.npmjs.com/package/papaparse) - HIGH confidence
- [csv-parse - npm](https://www.npmjs.com/package/csv-parse) - HIGH confidence
- [streaming-csv-worker GitHub](https://github.com/ctohm/streaming-csv-worker) - MEDIUM confidence (not on npm)
- [Parsing CSV files in Cloudflare Worker](https://blog.remeika.us/2023/07/07/parsing-csv-files.html) - MEDIUM confidence

**API SDKs:**
- [cloudflare npm package](https://www.npmjs.com/package/cloudflare) - HIGH confidence
- [cloudflare-typescript GitHub](https://github.com/cloudflare/cloudflare-typescript) - HIGH confidence

**Performance:**
- [We made Workers KV up to 3x faster](https://blog.cloudflare.com/faster-workers-kv/) - HIGH confidence
- [KV vs D1 benchmark](https://github.com/bruceharrison1984/kv-d1-benchmark) - MEDIUM confidence (community)
- [Hono Benchmarks](https://hono.dev/docs/concepts/benchmarks) - HIGH confidence
- [Hono Routers documentation](https://hono.dev/docs/concepts/routers) - HIGH confidence

**URLPattern API:**
- [URL Pattern API - MDN](https://developer.mozilla.org/en-US/docs/Web/API/URL_Pattern_API) - HIGH confidence
- [URLPattern API brings improved pattern matching](https://blog.cloudflare.com/improving-web-standards-urlpattern/) - HIGH confidence

**Drizzle ORM:**
- [Drizzle ORM - Cloudflare D1](https://orm.drizzle.team/docs/connect-cloudflare-d1) - HIGH confidence
- [D1 Community Projects](https://developers.cloudflare.com/d1/reference/community-projects/) - HIGH confidence

---
*Stack research for: SonicJS Redirect Plugin*
*Researched: 2026-01-30*
