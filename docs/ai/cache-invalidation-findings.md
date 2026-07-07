# Cache Invalidation — Findings & Recommendations

**Date:** 2026-07-06
**Scope:** How the cache plugin invalidates entries today, how mainstream cache systems solve list-vs-item invalidation, and what SonicJS should do next.

---

## 1. How SonicJS handles it today

### 1.1 Two invalidation mechanisms coexist

**A. Event-bus listeners** (`packages/core/src/plugins/cache/services/cache-invalidation.ts`)

`setupCacheInvalidation()` runs at plugin activation and registers listeners on an in-memory event bus:

| Event | Action |
|---|---|
| `content.create` / `content.publish` | wipe `content:*` + wipe `api:*` |
| `content.update` | delete `content:item:<id>`, wipe `content:list:*`, wipe `api:*` |
| `content.delete` | delete item key, wipe `content:*`, wipe `api:*` |
| `media.upload/update/delete` | delete item key, wipe `media:list:*` (or `media:*`) |
| `user.update/delete`, `auth.login/logout` | delete per-user / per-session keys |
| `config.update`, `plugin.*`, `collection.*` | wipe `config:*` / `plugin:*` / `collection:*` |

**Important:** only `api-media.ts` actually emits events (`media.upload`, `media.delete`, `media.update`, `media.move`). **No route emits `content.*`, `user.*`, `config.*`, `plugin.*`, or `collection.*` events.** Those listeners are dead wiring today — well-tested dead wiring (the unit tests emit the events manually), but nothing in production code fires them.

**B. Inline invalidation in route handlers** (the mechanism that actually runs for content)

Write handlers call `cache.invalidate(pattern)` directly after mutating:

- `admin-content.ts` (create/update/delete/bulk):
  - `cache.delete('content:content:<id>:v1')` — exact item key
  - `cache.invalidate('content:list:<collectionId>:*')` — per-collection lists (some paths)
  - `cache.invalidate('content:list:*')` — all lists (other paths)
  - `apiCache.invalidate('content-filtered:*')` + `apiCache.invalidate('collection-content-filtered:*')` — **all** public-API list caches
- `api.ts` and `api-content-crud.ts` (public CRUD): same two `api`-namespace wipes after every write.

### 1.2 So: how does a list cache "know" an item changed?

It doesn't. The strategy is **coarse pattern-based invalidation**: any write to any content item nukes **every** cached list response in the `api` namespace, across **all** collections. There is no dependency tracking between list caches and their member items.

Granularity today:

| Cache | Key shape | Invalidation on item write |
|---|---|---|
| Item | `content:content:<id>:v1` | exact-key delete ✅ |
| Admin lists | `content:list:<collectionId>:page:N` | per-collection wipe (some paths), global wipe (others) |
| API list (cross-collection) | `api:content-filtered:<json-of-filter+sql>:v1` | global wipe |
| API list (per-collection) | `api:collection-content-filtered:<collection>:<json>:v1` | **global wipe — even though the key already embeds the collection name** |

### 1.3 Safety nets & costs

- **TTL backstop**: `api` namespace = 300 s, `content` = 3600 s. Even a missed invalidation self-heals within TTL.
- **KV pattern invalidation is expensive**: KV has no pattern delete, so `invalidate()` does `list({prefix})` + regex test + one `delete()` per match (`cache.ts:359-392`). Sequential awaits, and KV list is eventually consistent — a just-written entry can survive the sweep.
- **Two-axis coverage gap**: memory tier is per-isolate. An invalidation runs in the isolate that handled the write; other isolates' memory tiers keep stale entries until TTL. KV tier is shared, so cross-isolate correctness leans on KV + short TTL.

### 1.4 Document-model gap

`DocumentsService` / `api-documents.ts` / `admin-documents.ts` have **zero cache integration** — no caching, no invalidation, no events. Legacy `admin-content.ts` handles its own invalidation inline, but any future read path that caches document queries has no invalidation hook to attach to. Worth deciding before the media read-flip completes.

---

## 2. How mainstream cache systems handle list invalidation

Ordered roughly from crude to sophisticated:

### 2.1 TTL-only ("eventual freshness")
Do nothing on write; let entries expire. Simple, zero write-path cost, bounded staleness. Fine for content where N-seconds staleness is acceptable. Most CDN caching defaults to this.

### 2.2 Purge-by-key
Writer deletes exact keys it knows about. Works for item caches; **fails for lists** because the writer can't enumerate every filter/sort/pagination combination that might contain the item. This is why SonicJS pairs it with pattern wipes.

### 2.3 Tag-based (a.k.a. surrogate keys) — the industry answer to your question
Each cache entry is stored with a set of **tags** describing what it depends on. Invalidation targets a tag, and the store drops every entry carrying it.

- Cloudflare `Cache-Tag` / Fastly `Surrogate-Key` headers, purge-by-tag APIs
- Laravel `Cache::tags(['posts'])->flush()`, Spring `@CacheEvict`, Next.js `revalidateTag()`
- A list response for collection `blog` gets tagged `collection:blog`; item `123` gets `content:123` + `collection:blog`
- Update/insert/delete of any blog item → purge tag `collection:blog` → every list containing blog content dies, nothing else does

This is exactly the "track at collection level" idea in the question — it's the standard, and the right granularity trade-off.

### 2.4 Per-item dependency tracking ("track items in a cache list")
Store, per cached list, the exact set of item IDs it contains; on item write, invalidate only lists containing that ID. Answering the question directly: **almost nobody does this, and you shouldn't**:

- **Inserts break it**: a brand-new item belongs to no existing list's ID-set, yet must invalidate every list whose filter it matches (e.g. "10 newest posts"). You'd have to evaluate every cached query's predicate against the new row — that's a query-subscription engine, not a cache.
- Deletes and updates-that-change-filter-membership have the same problem in reverse (an update can move an item *into* a list it wasn't in).
- Bookkeeping cost is O(items × lists) and must itself be stored/invalidated consistently.

Systems that genuinely need this precision (materialized views, Noria, Readyset, Meta's TAO) are database-layer incremental-view-maintenance engines. For an application cache, collection-level tags capture ~all of the benefit at ~none of the cost.

### 2.5 Versioned keys / generation counters (key-based expiry)
Instead of finding-and-deleting entries, embed a **generation number** in the key:

```
api:v{gen}:collection-content-filtered:blog:<query-hash>
```

On any write to collection `blog`, bump `gen(blog)` (one counter write). All old entries become unreachable instantly and age out via TTL — **O(1) invalidation, no enumeration**. Memcached's classic "namespace versioning" pattern; Rails calls it key-based cache expiration. Trade-off: orphaned entries occupy space until TTL evicts them.

### 2.6 Event-driven invalidation
Writes emit events; subscribers invalidate. What SonicJS's event bus was built for — decouples writers from cache layout. Caveat in Workers: an in-memory bus only reaches the isolate that handled the write (fine here because the shared KV tier is what matters cross-isolate).

---

## 3. Answers to the specific questions

**"How does it know to invalidate the cache?"**
It doesn't know — it over-invalidates. Every content write wipes all API list caches via `invalidate('content-filtered:*')` + `invalidate('collection-content-filtered:*')`, plus deletes the exact item key. Event listeners exist for content but nothing emits those events; inline route calls do the real work.

**"Do we need to track items in a cache list?"**
No. Per-item dependency tracking can't handle inserts (a new item is in no tracked list but must invalidate matching lists), so you end up needing collection-level invalidation anyway. Skip straight to it.

**"What about inserts and deletes?"**
They're the argument *for* collection-level granularity: any insert/delete/update within collection C can affect any list of C (ordering, counts, pagination, filter membership) — and cannot affect lists of other collections (cross-collection queries aside). So "write to C → invalidate everything tagged C" is both sound and minimal at reasonable cost.

**"Track at collection level, invalidate all caches that include that collection?"**
Yes — that is tag-based invalidation, and it's the recommended design. See below.

---

## 4. Recommendation for SonicJS

### 4.1 Adopt collection-scoped invalidation (cheap first step)
`collection-content-filtered` keys **already embed the collection name** (`api.ts:871`). Change write paths from:

```ts
await cache.invalidate('collection-content-filtered:*')        // all collections
```
to:
```ts
await cache.invalidate(`collection-content-filtered:${collection}:*`)  // one collection
```

Cross-collection queries (`content-filtered:*`) keep the global wipe (or get tagged with every collection they touch, later). Low-risk, no schema change, immediate reduction in cache churn.

### 4.2 Prefer generation counters over KV enumeration (right long-term shape)
KV list-and-delete is slow, sequential, and eventually consistent. Replace pattern-delete in the `api` namespace with a **per-collection generation**:

- Keep `gen(collection)` in memory + KV (`cache:gen:<collection>`)
- Cache keys include the generation: `api:collection-content-filtered:blog:g42:<hash>`
- On write: bump the counter (single KV `put`) — O(1), atomic-enough, no enumeration
- Stale entries expire via the existing 300 s TTL

This also fixes the cross-isolate staleness hole for the KV tier: a generation bump is visible to all isolates on their next read (memory tier still relies on TTL, as today).

### 4.3 Unify on the event bus (consistency)
Pick one mechanism. Either delete the dead `content.*`/`collection.*` listeners, or (better) make routes/services emit events and remove inline `invalidate()` calls. The event log already powers `/admin/cache/analytics` invalidation stats — inline calls are invisible there today, so the analytics under-report.

### 4.4 Wire the document model in (gap)
`DocumentsService.create/saveDraft/publish/unpublish/erase` should emit `content.*`-equivalent events (or call a single `invalidateCollection(collection)` helper) so that when document reads get cached — or when legacy routes flip to the document path — invalidation doesn't silently disappear. Collection name is available at every DocumentsService call site.

### 4.5 Non-goals
- Per-item → list dependency tracking (see §2.4 — insert problem, bookkeeping cost)
- Query-predicate matching / incremental view maintenance — database-layer tech, wrong altitude for this cache
- Shortening TTLs as a substitute for correct invalidation — the 300 s `api` TTL is a good backstop; keep it as backstop, not primary mechanism

---

## 5. File reference

| Concern | Location |
|---|---|
| Event listeners (invalidation rules) | `packages/core/src/plugins/cache/services/cache-invalidation.ts` |
| Pattern invalidation impl (memory + KV sweep) | `packages/core/src/plugins/cache/services/cache.ts:359` |
| Key format / namespaces / TTLs | `packages/core/src/plugins/cache/services/cache-config.ts` |
| Event bus | `packages/core/src/plugins/cache/services/event-bus.ts` |
| Inline invalidation — admin writes | `packages/core/src/routes/admin-content.ts:1264,1303,1414,1548,1926,1984` |
| Inline invalidation — public API writes | `packages/core/src/routes/api.ts:1117,1171,1211`, `api-content-crud.ts:246,328,384` |
| Only event emitter in production code | `packages/core/src/routes/api-media.ts` |
| List cache key with collection embedded | `packages/core/src/routes/api.ts:871` |
