/**
 * URL Catalog — tracks cache-eligible API requests for smart pre-warming.
 * Per-isolate in-memory cache, with KV-backed persistence so all isolates
 * share the same catalog (cross-isolate visibility in the admin dashboard).
 */

interface KVLike {
  list(opts: { prefix: string }): Promise<{ keys: { name: string }[] }>
  get(key: string, type: 'json'): Promise<unknown>
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>
  delete(key: string): Promise<void>
}

interface CtxLike {
  waitUntil(p: Promise<unknown>): void
}

const MAX_CATALOG_SIZE = 500
const KV_TTL = 2_592_000 // 30 days
const KV_THROTTLE_MS = 30_000 // write at most once per 30s per key

export interface CatalogEntry {
  cacheKey: string
  collection: string | null
  path: string
  queryString: string
  hits: number
  misses: number
  staleServes: number
  lastSeen: number
  firstSeen: number
}

const catalog = new Map<string, CatalogEntry>()
const kvThrottle = new Map<string, number>() // cacheKey → last KV write ms

let globalKv: KVLike | null = null

export function setGlobalCatalogKv(kv: KVLike): void {
  globalKv = kv
}

export function recordCatalogRequest(opts: {
  cacheKey: string
  collection: string | null
  path: string
  queryString: string
  source: 'memory' | 'kv' | 'miss' | 'swr'
}): void {
  const { cacheKey, collection, path, queryString, source } = opts
  const now = Date.now()
  const existing = catalog.get(cacheKey)
  if (existing) {
    if (source === 'miss') existing.misses++
    else if (source === 'swr') existing.staleServes++
    else existing.hits++
    existing.lastSeen = now
    return
  }
  // Evict oldest entry when at capacity
  if (catalog.size >= MAX_CATALOG_SIZE) {
    let oldestKey = ''
    let oldestSeen = Infinity
    for (const [k, e] of catalog.entries()) {
      if (e.lastSeen < oldestSeen) { oldestSeen = e.lastSeen; oldestKey = k }
    }
    if (oldestKey) catalog.delete(oldestKey)
  }
  catalog.set(cacheKey, {
    cacheKey,
    collection,
    path,
    queryString,
    hits: source !== 'miss' && source !== 'swr' ? 1 : 0,
    misses: source === 'miss' ? 1 : 0,
    staleServes: source === 'swr' ? 1 : 0,
    lastSeen: now,
    firstSeen: now,
  })
}

/** Hash a cache key to a short fixed-length string safe for use as a KV key. */
async function kvSafeKey(cacheKey: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(cacheKey))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32)
}

/** Schedule a throttled KV write for the given cache key. Call after recordCatalogRequest(). */
export function scheduleKvWrite(cacheKey: string, ctx: CtxLike | null | undefined): void {
  if (!globalKv || !ctx) return
  const entry = catalog.get(cacheKey)
  if (!entry) return
  const now = Date.now()
  if ((kvThrottle.get(cacheKey) ?? 0) > now - KV_THROTTLE_MS) return
  kvThrottle.set(cacheKey, now)
  const kv = globalKv
  ctx.waitUntil(
    kvSafeKey(cacheKey).then(h => kv.put(`_catalog:${h}`, JSON.stringify(entry), { expirationTtl: KV_TTL }))
  )
}

/** Load all KV-persisted catalog entries and merge into the in-memory map. */
export async function loadKvCatalog(): Promise<void> {
  if (!globalKv) return
  try {
    const list = await globalKv.list({ prefix: '_catalog:' })
    await Promise.all(list.keys.map(async ({ name }) => {
      const entry = (await globalKv!.get(name, 'json')) as CatalogEntry | null
      if (!entry?.cacheKey) return
      const existing = catalog.get(entry.cacheKey)
      if (existing) {
        existing.hits = Math.max(existing.hits, entry.hits)
        existing.misses = Math.max(existing.misses, entry.misses)
        existing.staleServes = Math.max(existing.staleServes, entry.staleServes)
        existing.lastSeen = Math.max(existing.lastSeen, entry.lastSeen)
        existing.firstSeen = Math.min(existing.firstSeen, entry.firstSeen)
      } else {
        catalog.set(entry.cacheKey, entry)
      }
    }))
  } catch (err) {
    console.error('[Catalog] KV load error:', err)
  }
}

/** Delete all KV-persisted catalog entries. */
export async function clearKvCatalog(): Promise<void> {
  if (!globalKv) return
  try {
    const list = await globalKv.list({ prefix: '_catalog:' })
    await Promise.all(list.keys.map(({ name }) => globalKv!.delete(name)))
  } catch (err) {
    console.error('[Catalog] KV clear error:', err)
  }
}

export function getCatalog(opts?: {
  collection?: string
  sortBy?: 'hits' | 'requests' | 'misses'
  limit?: number
}): CatalogEntry[] {
  let entries = Array.from(catalog.values())
  if (opts?.collection) entries = entries.filter(e => e.collection === opts.collection)
  const sortBy = opts?.sortBy ?? 'requests'
  entries.sort((a, b) => {
    if (sortBy === 'hits') return b.hits - a.hits
    if (sortBy === 'misses') return b.misses - a.misses
    return (b.hits + b.misses + b.staleServes) - (a.hits + a.misses + a.staleServes)
  })
  return entries.slice(0, opts?.limit ?? 100)
}

export function getCatalogStats() {
  const entries = Array.from(catalog.values())
  return {
    totalEntries: entries.length,
    totalHits: entries.reduce((s, e) => s + e.hits, 0),
    totalMisses: entries.reduce((s, e) => s + e.misses, 0),
    totalStale: entries.reduce((s, e) => s + e.staleServes, 0),
    collections: [...new Set(entries.map(e => e.collection).filter((c): c is string => c !== null))],
  }
}

export function clearCatalog(): void {
  catalog.clear()
}
