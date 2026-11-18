/**
 * Stale-While-Revalidate store.
 * Per-isolate, in-memory. A reader that finds an entry here serves it immediately instead of
 * taking a cold DB hit.
 *
 * `markStale` currently has no callers. The write paths in `routes/api.ts` used to stash the
 * values they were about to invalidate, but `getAndConsumeStale` serves the stashed value as-is
 * and never schedules a revalidation, so the first read after any write returned pre-write data.
 * Only stash entries that are stale through TTL expiry — never ones an explicit `invalidate`
 * just retired — and give the serve path a background refresh before wiring this back up.
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
