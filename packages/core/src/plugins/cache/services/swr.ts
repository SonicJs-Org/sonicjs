/**
 * Stale-While-Revalidate store.
 * Per-isolate, in-memory. When a cache entry is about to be invalidated,
 * callers stash it here so the next request can serve the stale value
 * immediately instead of a cold DB hit.
 */

const STALE_TTL_MS = 30_000 // 30-second stale window

interface StaleEntry {
  data: unknown
  collection: string | null
  expiresAt: number
}

const staleMap = new Map<string, StaleEntry>()

export function markStale(cacheKey: string, data: unknown, collection: string | null): void {
  staleMap.set(cacheKey, {
    data,
    collection,
    expiresAt: Date.now() + STALE_TTL_MS,
  })
}

/** Retrieve and consume the stale entry (one serve per invalidation). */
export function getAndConsumeStale(cacheKey: string): unknown | null {
  const entry = staleMap.get(cacheKey)
  if (!entry) return null
  if (Date.now() > entry.expiresAt) {
    staleMap.delete(cacheKey)
    return null
  }
  staleMap.delete(cacheKey)
  return entry.data
}

export function swrStats(): { count: number } {
  // Purge expired entries before counting
  const now = Date.now()
  for (const [key, entry] of staleMap.entries()) {
    if (now > entry.expiresAt) staleMap.delete(key)
  }
  return { count: staleMap.size }
}
