# Architecture Research: SonicJS Redirect Plugin

**Domain:** URL redirect management plugin for SonicJS CMS
**Researched:** 2026-01-30
**Confidence:** HIGH

## Recommended Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         REQUEST PIPELINE                             │
├─────────────────────────────────────────────────────────────────────┤
│  Incoming Request                                                    │
│       ↓                                                              │
│  [Redirect Middleware] ←──── In-Memory Cache (50ms TTL)             │
│       ↓ (if match)           ↑                                      │
│  [302/301 Response]          │                                      │
│       ↓ (if no match)        │                                      │
│  [Continue to Router] ───────┘                                      │
├─────────────────────────────────────────────────────────────────────┤
│                         ADMIN INTERFACE                              │
├─────────────────────────────────────────────────────────────────────┤
│  [Admin UI Routes]                                                   │
│       │                                                              │
│       ├── Settings Page (import/export/manage)                      │
│       ├── Redirect List (view/search/filter)                        │
│       └── API Routes (CRUD operations)                               │
│                ↓                                                     │
│       [Redirect Service] ──→ [D1 Database]                          │
│                ↓                                                     │
│       [CF Bulk Redirects API] (optional)                            │
├─────────────────────────────────────────────────────────────────────┤
│                         DATA LAYER                                   │
├─────────────────────────────────────────────────────────────────────┤
│  [redirects Collection] ──→ Auto-generated Admin UI & API           │
│       │                                                              │
│       └── Fields: source, target, status_code, active, priority     │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Integration Point |
|-----------|----------------|-------------------|
| **Redirect Middleware** | Intercept requests early in pipeline, check for redirect match, return redirect response or pass through | Hono middleware registered with `priority: 1` (runs before routing) |
| **Redirect Service** | Business logic for redirect CRUD, validation, cache invalidation, CSV import/export | Used by admin routes and middleware |
| **Redirects Collection** | Declarative schema defining redirect data structure, auto-generates admin UI and REST API | SonicJS collection system in `/collections/redirects.collection.ts` |
| **Admin Routes** | HTTP handlers for settings page, bulk import/export, redirect management | Mounted at `/admin/plugins/redirects` |
| **Cache Layer** | In-memory Map with TTL for fast lookups (critical for performance) | Integrated with SonicJS cache plugin or standalone |
| **CF Bulk Redirects Sync** | Optional: sync redirects to Cloudflare's edge redirect service | Service method called on-demand or via webhook |

## Recommended Project Structure

```
src/plugins/redirects/
├── index.ts                         # Plugin entry point (PluginBuilder)
├── manifest.json                    # Plugin metadata
├── types.ts                         # TypeScript interfaces
├── collections/
│   └── redirects.collection.ts      # Declarative collection schema
├── middleware/
│   └── redirect.ts                  # Early-pipeline redirect interceptor
├── services/
│   ├── redirect.ts                  # Core business logic (CRUD, validation)
│   ├── cache.ts                     # In-memory redirect cache
│   ├── csv-import.ts                # CSV parsing and validation
│   └── cloudflare-sync.ts           # Optional CF Bulk Redirects API
├── routes/
│   ├── admin.ts                     # Admin API routes
│   └── public.ts                    # Public API (if needed)
├── components/
│   ├── settings-page.ts             # Admin UI for import/export/settings
│   └── redirect-list.ts             # Admin UI for redirect management
├── migrations/
│   └── 001_redirects_plugin.sql     # Database schema (if not using collections)
└── test/
    ├── redirect.spec.ts             # E2E tests
    └── csv-import.spec.ts           # CSV import tests
```

### Structure Rationale

- **collections/**: SonicJS collections auto-generate admin UI and CRUD APIs, reducing boilerplate. The redirect data structure maps cleanly to a collection schema.
- **middleware/**: Early-pipeline interception is critical for redirect performance. Hono middleware with `priority: 1` ensures redirects are checked before route resolution.
- **services/**: Business logic is separated from HTTP handlers, making it testable and reusable across admin UI, API, and middleware.
- **cache.ts**: Standalone cache service allows flexibility to integrate with SonicJS cache plugin or use a simple Map for MVP.
- **cloudflare-sync.ts**: Isolated service for optional CF Bulk Redirects integration. Not required for MVP, but architected for future enhancement.

## Architectural Patterns

### Pattern 1: Collection-First Data Modeling

**What:** Use SonicJS collections to define the redirect schema declaratively. Collections auto-generate admin UI, REST API, and database schema.

**When to use:** When the data model is straightforward and you want to minimize boilerplate.

**Trade-offs:**
- **Pro:** Rapid development, automatic admin UI, consistent API patterns
- **Pro:** Schema validation via Zod, integrated with SonicJS admin
- **Con:** Less control over API response format (but can be extended)

**Example:**
```typescript
// collections/redirects.collection.ts
export default {
  name: 'redirects',
  displayName: 'Redirects',
  description: 'URL redirects for SEO and site navigation',
  icon: '↗️',

  schema: {
    type: 'object',
    properties: {
      source: {
        type: 'string',
        title: 'Source Path',
        required: true,
        placeholder: '/old-path',
        helpText: 'Path to redirect from (e.g., /old-page)'
      },
      target: {
        type: 'string',
        title: 'Target URL',
        required: true,
        placeholder: '/new-path or https://example.com',
        helpText: 'Destination URL (can be relative or absolute)'
      },
      statusCode: {
        type: 'select',
        title: 'Status Code',
        enum: [301, 302, 307, 308],
        enumLabels: ['301 Permanent', '302 Temporary', '307 Temporary (preserve method)', '308 Permanent (preserve method)'],
        default: 302,
        required: true
      },
      active: {
        type: 'checkbox',
        title: 'Active',
        default: true,
        helpText: 'Enable or disable this redirect'
      },
      priority: {
        type: 'number',
        title: 'Priority',
        min: 1,
        max: 100,
        default: 50,
        helpText: 'Higher priority redirects are checked first'
      }
    },
    required: ['source', 'target', 'statusCode']
  },

  listFields: ['source', 'target', 'statusCode', 'active'],
  searchFields: ['source', 'target'],
  defaultSort: 'priority',
  defaultSortOrder: 'desc'
} satisfies CollectionConfig
```

### Pattern 2: Early-Pipeline Middleware

**What:** Register middleware with high priority (`priority: 1`) to intercept requests before route resolution. Check for redirect match, return redirect response immediately if found.

**When to use:** When performance is critical and you need to avoid route processing overhead.

**Trade-offs:**
- **Pro:** Minimal latency (executes before routing)
- **Pro:** Works with any request path (not limited to defined routes)
- **Con:** Middleware runs on every request (mitigated by cache)

**Example:**
```typescript
// middleware/redirect.ts
import type { Context, Next } from 'hono'
import { getRedirectCache } from '../services/cache'

export async function redirectMiddleware(c: Context, next: Next) {
  const path = new URL(c.req.url).pathname

  // Check in-memory cache first (50ms TTL)
  const cache = getRedirectCache()
  const redirect = await cache.get(path)

  if (redirect && redirect.active) {
    return c.redirect(redirect.target, redirect.statusCode)
  }

  // No redirect found, continue to routing
  await next()
}
```

### Pattern 3: Layered Caching Strategy

**What:** Use in-memory Map with short TTL (50-100ms) to cache redirect lookups. This provides sub-millisecond lookup times while keeping data reasonably fresh.

**When to use:** When redirect lookups happen on every request and performance is critical.

**Trade-offs:**
- **Pro:** Sub-millisecond lookup times (Map access)
- **Pro:** Automatic staleness handling via TTL
- **Con:** Cache is region-specific (Cloudflare Workers are stateless across regions)
- **Con:** Memory usage (mitigated by TTL expiration)

**Example:**
```typescript
// services/cache.ts
interface CachedRedirect {
  source: string
  target: string
  statusCode: number
  active: boolean
  expiresAt: number
}

class RedirectCache {
  private cache = new Map<string, CachedRedirect>()
  private ttl = 50 // milliseconds

  async get(source: string): Promise<CachedRedirect | null> {
    const entry = this.cache.get(source)

    if (!entry) return null

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(source)
      return null
    }

    return entry
  }

  set(source: string, redirect: Omit<CachedRedirect, 'expiresAt'>): void {
    this.cache.set(source, {
      ...redirect,
      expiresAt: Date.now() + this.ttl
    })
  }

  invalidate(source?: string): void {
    if (source) {
      this.cache.delete(source)
    } else {
      this.cache.clear()
    }
  }
}

// Singleton instance
let cacheInstance: RedirectCache | null = null

export function getRedirectCache(): RedirectCache {
  if (!cacheInstance) {
    cacheInstance = new RedirectCache()
  }
  return cacheInstance
}
```

### Pattern 4: Service-Oriented Business Logic

**What:** Separate business logic into service classes that are agnostic to HTTP transport. Services are injected with D1 database and called by routes, middleware, and lifecycle hooks.

**When to use:** When you need testable, reusable logic that isn't tied to HTTP.

**Trade-offs:**
- **Pro:** Highly testable (mock database)
- **Pro:** Reusable across HTTP handlers and background jobs
- **Con:** Additional abstraction layer (minimal cost)

**Example:**
```typescript
// services/redirect.ts
import type { D1Database } from '@cloudflare/workers-types'
import { getRedirectCache } from './cache'

export interface Redirect {
  id?: string
  source: string
  target: string
  statusCode: number
  active: boolean
  priority: number
  createdAt?: number
  updatedAt?: number
}

export class RedirectService {
  constructor(private db: D1Database) {}

  async findBySource(source: string): Promise<Redirect | null> {
    // Check cache first
    const cache = getRedirectCache()
    const cached = await cache.get(source)
    if (cached) return cached

    // Query database
    const result = await this.db
      .prepare('SELECT * FROM redirects WHERE source = ? AND active = 1 LIMIT 1')
      .bind(source)
      .first()

    if (!result) return null

    const redirect = this.mapDbRowToRedirect(result)

    // Cache result
    cache.set(source, redirect)

    return redirect
  }

  async create(redirect: Omit<Redirect, 'id' | 'createdAt' | 'updatedAt'>): Promise<string> {
    const id = crypto.randomUUID()
    const now = Date.now()

    await this.db
      .prepare(`
        INSERT INTO redirects (id, source, target, status_code, active, priority, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(id, redirect.source, redirect.target, redirect.statusCode, redirect.active ? 1 : 0, redirect.priority, now, now)
      .run()

    // Invalidate cache for this source
    getRedirectCache().invalidate(redirect.source)

    return id
  }

  async update(id: string, updates: Partial<Redirect>): Promise<void> {
    // Get current redirect to invalidate cache
    const current = await this.db
      .prepare('SELECT source FROM redirects WHERE id = ?')
      .bind(id)
      .first()

    const now = Date.now()
    const fields: string[] = []
    const values: any[] = []

    if (updates.source !== undefined) {
      fields.push('source = ?')
      values.push(updates.source)
    }
    if (updates.target !== undefined) {
      fields.push('target = ?')
      values.push(updates.target)
    }
    if (updates.statusCode !== undefined) {
      fields.push('status_code = ?')
      values.push(updates.statusCode)
    }
    if (updates.active !== undefined) {
      fields.push('active = ?')
      values.push(updates.active ? 1 : 0)
    }
    if (updates.priority !== undefined) {
      fields.push('priority = ?')
      values.push(updates.priority)
    }

    fields.push('updated_at = ?')
    values.push(now)
    values.push(id)

    await this.db
      .prepare(`UPDATE redirects SET ${fields.join(', ')} WHERE id = ?`)
      .bind(...values)
      .run()

    // Invalidate cache for old and new sources
    if (current?.source) {
      getRedirectCache().invalidate(current.source as string)
    }
    if (updates.source && updates.source !== current?.source) {
      getRedirectCache().invalidate(updates.source)
    }
  }

  async delete(id: string): Promise<void> {
    // Get source to invalidate cache
    const redirect = await this.db
      .prepare('SELECT source FROM redirects WHERE id = ?')
      .bind(id)
      .first()

    await this.db
      .prepare('DELETE FROM redirects WHERE id = ?')
      .bind(id)
      .run()

    if (redirect?.source) {
      getRedirectCache().invalidate(redirect.source as string)
    }
  }

  private mapDbRowToRedirect(row: any): Redirect {
    return {
      id: row.id,
      source: row.source,
      target: row.target,
      statusCode: row.status_code,
      active: row.active === 1,
      priority: row.priority,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }
  }
}
```

## Data Flow

### Request Flow (Redirect Hit)

```
1. User Request: GET /old-page
   ↓
2. Redirect Middleware executes (priority: 1, runs before routing)
   ↓
3. Check In-Memory Cache for "/old-page"
   ↓ (cache hit)
4. Return: HTTP 302 Location: /new-page
   ↓
5. Browser follows redirect
   ↓
6. User lands on /new-page
```

**Timing:** ~0.1ms (cache hit) to ~5ms (cache miss, requires DB query)

### Request Flow (No Redirect)

```
1. User Request: GET /some-page
   ↓
2. Redirect Middleware executes
   ↓
3. Check In-Memory Cache for "/some-page"
   ↓ (cache miss)
4. Call next() to continue pipeline
   ↓
5. Hono routing resolves /some-page
   ↓
6. Normal page render
```

**Overhead:** ~0.05ms (cache lookup) + negligible (middleware pass-through)

### Admin Flow (Create Redirect)

```
1. Admin: POST /admin/api/redirects
   Body: { source: "/old", target: "/new", statusCode: 302 }
   ↓
2. Admin Route Handler validates request
   ↓
3. Calls RedirectService.create()
   ↓
4. Service inserts row into D1 database
   ↓
5. Service invalidates cache for "/old"
   ↓
6. Response: { success: true, id: "uuid" }
   ↓
7. Next request to "/old" misses cache, queries DB, caches result
```

### CSV Import Flow

```
1. Admin: POST /admin/api/redirects/import
   Body: CSV file (multipart/form-data)
   ↓
2. Route handler parses CSV
   ↓
3. Validates each redirect (source, target, statusCode)
   ↓
4. Calls RedirectService.bulkCreate()
   ↓
5. Service uses D1 batch insert (transaction)
   ↓
6. Service clears entire redirect cache
   ↓
7. Response: { success: true, imported: 150, failed: 2, errors: [...] }
```

## Cloudflare Integration Strategy

### Option 1: Plugin-Managed Redirects (Recommended for MVP)

**What:** Redirects are stored in D1, cached in-memory, and handled by middleware. No Cloudflare Bulk Redirects API.

**Pros:**
- Simpler implementation (no API integration)
- Faster development (MVP-ready)
- Full control over redirect logic

**Cons:**
- Redirect latency is region-specific (cache is per-region)
- Redirects happen in Workers (not at edge before Workers)

### Option 2: Sync to Cloudflare Bulk Redirects (Post-MVP)

**What:** Plugin maintains redirects in D1 for admin UI, but syncs them to Cloudflare's Bulk Redirects API for edge-level redirect performance.

**Pros:**
- Redirects happen at edge (before Workers execute)
- Global consistency (CF Bulk Redirects are global)
- No middleware overhead on requests

**Cons:**
- Complex integration (CF API, auth, rate limits)
- Eventual consistency (sync delay)
- Debugging is harder (redirects not in code)

**Implementation:**
```typescript
// services/cloudflare-sync.ts
export class CloudflareSyncService {
  private apiUrl = 'https://api.cloudflare.com/client/v4'

  constructor(
    private accountId: string,
    private apiToken: string
  ) {}

  async syncRedirects(redirects: Redirect[]): Promise<void> {
    // 1. Create/update Bulk Redirect List
    const listId = await this.ensureRedirectList()

    // 2. Clear existing items
    await this.clearListItems(listId)

    // 3. Add new items (batch of 1000)
    const items = redirects.map(r => ({
      source_url: r.source,
      target_url: r.target,
      status_code: r.statusCode
    }))

    for (let i = 0; i < items.length; i += 1000) {
      const batch = items.slice(i, i + 1000)
      await this.addListItems(listId, batch)
    }

    // 4. Create/update Bulk Redirect Rule
    await this.ensureRedirectRule(listId)
  }

  private async ensureRedirectList(): Promise<string> {
    // Implementation: GET or POST to /accounts/{accountId}/rules/lists
    // ...
  }

  // ... other CF API methods
}
```

**When to implement:** After MVP is validated, when redirect volume justifies edge-level optimization.

## Integration Points

### 1. Middleware Registration

**Where:** `index.ts` plugin entry point
**How:** Use `PluginBuilder.addSingleMiddleware()` with `global: true` and `priority: 1`

```typescript
// index.ts
import { PluginBuilder } from '@sonicjs-cms/core'
import { redirectMiddleware } from './middleware/redirect'

const builder = PluginBuilder.create({
  name: 'redirects',
  version: '1.0.0',
  description: 'URL redirect management'
})

builder.addSingleMiddleware(
  'redirect-interceptor',
  redirectMiddleware,
  {
    description: 'Intercepts requests and applies redirects',
    priority: 1, // Execute early
    global: true // Apply to all routes
  }
)
```

**Critical:** Priority must be low (1-5) to ensure middleware runs before route resolution.

### 2. Collection Definition

**Where:** `collections/redirects.collection.ts`
**How:** Export CollectionConfig object, SonicJS auto-loads it

**Integration:** SonicJS scans `/collections/*.collection.ts` on boot and registers collections. This auto-generates:
- Admin UI at `/admin/redirects`
- REST API at `/api/redirects` (GET, POST, PUT, DELETE)
- Database schema validation

### 3. Admin Routes

**Where:** `routes/admin.ts` mounted at `/admin/plugins/redirects`
**How:** Register via `PluginBuilder.addRoute()`

```typescript
builder.addRoute('/admin/plugins/redirects', adminRoutes, {
  description: 'Redirect admin interface',
  requiresAuth: true,
  priority: 100
})
```

### 4. Cache Invalidation Hooks

**Where:** `services/redirect.ts` emits events on CRUD operations
**How:** Use SonicJS event bus or cache plugin's invalidation system

```typescript
// After creating/updating/deleting a redirect
import { emitEvent } from '@sonicjs-cms/core/plugins'

emitEvent('redirect:invalidate', { source: redirect.source })
```

**Integration with cache plugin:**
```typescript
// In lifecycle activate() hook
context.hooks.register('redirect:invalidate', async (data) => {
  getRedirectCache().invalidate(data.source)
})
```

### 5. SonicJS Types Integration

**Where:** `types.ts` imports from `@sonicjs-cms/core`
**How:** Use D1Database, PluginContext, etc.

```typescript
import type { D1Database, PluginContext } from '@sonicjs-cms/core'

export interface RedirectPluginContext extends PluginContext {
  // Plugin-specific extensions
}
```

## Scaling Considerations

| Metric | 100 redirects | 1,000 redirects | 10,000 redirects |
|--------|---------------|-----------------|------------------|
| **Memory** | ~10KB cache | ~100KB cache | ~1MB cache |
| **DB Queries** | Cache misses: ~5ms | Cache misses: ~5ms | Cache misses: ~5-10ms (index required) |
| **Middleware Overhead** | ~0.05ms (cache hit) | ~0.05ms (cache hit) | ~0.05ms (cache hit) |
| **Import Time** | <1s | ~2s | ~10s (batched) |
| **Recommendation** | In-memory cache + D1 | In-memory cache + D1 | Consider CF Bulk Redirects API |

### Optimization Strategies

**At 100-1,000 redirects:**
- In-memory cache with 50ms TTL is sufficient
- Simple Map lookup is O(1) and sub-millisecond

**At 1,000-10,000 redirects:**
- Ensure database index on `source` column
- Consider increasing cache TTL to 100-200ms
- Monitor cache hit rate (should be >95%)

**At 10,000+ redirects:**
- Strongly consider syncing to CF Bulk Redirects API
- Edge-level redirects bypass Workers entirely
- Plugin becomes UI/management layer only

## Anti-Patterns to Avoid

### Anti-Pattern 1: Querying Database on Every Request

**What:** Skipping the in-memory cache and querying D1 directly for every redirect check.

**Why bad:** D1 queries add 5-10ms latency on every request, even for non-redirects. This compounds with request volume.

**Instead:** Use in-memory cache with short TTL (50-100ms). Cache misses are rare, and 50ms staleness is acceptable for redirects.

### Anti-Pattern 2: Using SonicJS Content API for Redirects

**What:** Storing redirects as generic content entries and using the content API for lookups.

**Why bad:** Content API is optimized for CRUD operations, not high-frequency lookups. Adds unnecessary abstraction and latency.

**Instead:** Use a dedicated redirects table (or collection) with optimized queries and custom caching.

### Anti-Pattern 3: Middleware After Routing

**What:** Registering redirect middleware with default priority (50+), which runs after route resolution.

**Why bad:** Routes will 404 before middleware runs. The redirect never triggers.

**Instead:** Use `priority: 1` to ensure middleware runs before routing.

### Anti-Pattern 4: Global Cache Invalidation on Every Update

**What:** Clearing the entire redirect cache when a single redirect is updated.

**Why bad:** Forces cache misses for all redirects, causing temporary performance degradation.

**Instead:** Invalidate only the affected source path(s). Use targeted invalidation.

### Anti-Pattern 5: No Validation on CSV Import

**What:** Accepting CSV imports without validating source/target paths, status codes, or duplicates.

**Why bad:** Invalid redirects break routing, circular redirects cause infinite loops, duplicates cause unpredictable behavior.

**Instead:** Validate each redirect before import:
- Check source path format (must start with `/`)
- Check target URL format (relative or absolute)
- Check status code (301, 302, 307, 308)
- Detect duplicates (same source path)
- Detect circular redirects (source === target, or A→B→A)

## Build Order Dependencies

### Phase 1: Core Infrastructure (MVP)

**Goal:** Basic redirect functionality working end-to-end.

**Components:**
1. **Collection Schema** (`collections/redirects.collection.ts`)
   - Defines data structure
   - Auto-generates admin UI and API
   - **Dependency:** None (foundational)

2. **Redirect Service** (`services/redirect.ts`)
   - CRUD operations
   - Database queries
   - **Dependency:** Collection schema (table structure)

3. **In-Memory Cache** (`services/cache.ts`)
   - Simple Map-based cache
   - TTL expiration
   - **Dependency:** Redirect data structure (types)

4. **Redirect Middleware** (`middleware/redirect.ts`)
   - Early-pipeline interception
   - Cache integration
   - **Dependency:** Cache service, Redirect service

5. **Plugin Entry Point** (`index.ts`)
   - PluginBuilder configuration
   - Middleware registration
   - Lifecycle hooks
   - **Dependency:** All above components

**Validation:** After Phase 1, you should be able to:
- Create redirects via auto-generated admin UI
- Request a redirect path and get redirected
- Observe sub-millisecond redirect latency (cache hit)

### Phase 2: Admin Enhancement

**Goal:** Improve admin UX with bulk operations and custom UI.

**Components:**
1. **CSV Import Service** (`services/csv-import.ts`)
   - Parse CSV files
   - Validate redirects
   - Batch insert
   - **Dependency:** Redirect service

2. **CSV Export Service** (`services/csv-export.ts`)
   - Query all redirects
   - Generate CSV
   - **Dependency:** Redirect service

3. **Admin Routes** (`routes/admin.ts`)
   - Bulk import/export endpoints
   - Settings management
   - **Dependency:** CSV services

4. **Settings Page Component** (`components/settings-page.ts`)
   - Custom UI for import/export
   - Settings form
   - **Dependency:** Admin routes

**Validation:** After Phase 2, you should be able to:
- Import 100+ redirects from CSV in <2 seconds
- Export all redirects to CSV
- View redirect statistics (total, active, inactive)

### Phase 3: Advanced Features (Post-MVP)

**Goal:** Optimize for scale and add Cloudflare integration.

**Components:**
1. **Cloudflare Sync Service** (`services/cloudflare-sync.ts`)
   - CF Bulk Redirects API integration
   - Batch sync operations
   - **Dependency:** Redirect service, CF API credentials

2. **Advanced Caching** (integrate with cache plugin)
   - KV storage for cross-region consistency
   - Cache warming on boot
   - **Dependency:** SonicJS cache plugin

3. **Analytics** (redirect hit tracking)
   - Log redirect usage
   - View popular redirects
   - **Dependency:** Analytics plugin or custom service

**Validation:** After Phase 3, you should be able to:
- Sync redirects to CF Bulk Redirects API
- Measure redirect hit rates
- Identify unused redirects for cleanup

## Performance Benchmarks

### Target Performance Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Redirect latency (cache hit) | <0.5ms | Middleware execution time |
| Redirect latency (cache miss) | <10ms | Middleware + DB query time |
| Middleware overhead (no redirect) | <0.1ms | Cache lookup time |
| CSV import (1000 redirects) | <3s | Bulk insert transaction |
| Cache invalidation | <1ms | Map delete operation |

### Optimization Checklist

- [ ] Database index on `redirects.source` column
- [ ] In-memory cache with 50-100ms TTL
- [ ] Middleware priority set to 1 (early execution)
- [ ] Batch insert for CSV imports (transaction)
- [ ] Targeted cache invalidation (not global clear)
- [ ] Monitoring for cache hit rate (target >95%)

## Sources

### Official Documentation (HIGH confidence)
- [Cloudflare Workers Redirects](https://developers.cloudflare.com/workers/static-assets/redirects/)
- [Cloudflare Bulk Redirects API](https://developers.cloudflare.com/rules/url-forwarding/bulk-redirects/create-api/)
- [Hono Middleware Guide](https://hono.dev/docs/guides/middleware)

### SonicJS Codebase (HIGH confidence)
- Contact Form Plugin: `/my-sonicjs-app/src/plugins/contact-form/`
- Cache Plugin: `/packages/core/src/plugins/cache/`
- Plugin Manager: `/packages/core/src/plugins/plugin-manager.ts`
- Plugin SDK: `/packages/core/src/plugins/sdk/plugin-builder.ts`
- Turnstile Middleware: `/packages/core/src/plugins/core-plugins/turnstile-plugin/middleware/verify.ts`

### Community Resources (MEDIUM confidence)
- [Cloudflare Blog: Bulk Redirects](https://blog.cloudflare.com/maximum-redirects-minimum-effort-announcing-bulk-redirects/)
- [Fishtank: Transitioning to Bulk Redirects](https://www.getfishtank.com/insights/transitioning-from-cloudflare-workers-to-bulk-redirects)

---
*Architecture research for: SonicJS Redirect Plugin*
*Researched: 2026-01-30*
*Confidence: HIGH - Based on SonicJS codebase analysis and official Cloudflare documentation*
