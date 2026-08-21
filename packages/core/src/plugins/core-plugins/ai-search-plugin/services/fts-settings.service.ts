/**
 * Lexical FTS5 settings, persisted in CACHE_KV.
 *
 * The `plugins` table is declared in db/schema.ts but has NO raw migration, so it does not exist on a
 * greenfield D1 — the legacy `SELECT settings FROM plugins` path always falls to its catch and returns
 * defaults (L24/L25). So FTS tuning is stored in KV under a fixed key instead. When no KV binding is
 * present, sensible defaults are used (search still works, just untunable).
 */
import type { KVNamespace } from '@cloudflare/workers-types'

export interface FtsSettings {
  titleBoost: number // bm25 weight for the title column
  slugBoost: number // bm25 weight for the slug column
  bodyBoost: number // bm25 weight for the body column
  resultsLimit: number // default page size
  cacheTtlSeconds: number // result-cache TTL; 0 disables caching
  searchableTypes: string[] // document type ids to search; empty = all
}

export const DEFAULT_FTS_SETTINGS: FtsSettings = {
  titleBoost: 5,
  slugBoost: 2,
  bodyBoost: 1,
  resultsLimit: 20,
  // Result caching is OFF by default. The KV result cache is keyed by query+tenant and is currently
  // only invalidated on settings change — NOT on document writes. With it on, an unpublished or deleted
  // doc keeps appearing in public search for the whole TTL window (a correctness/security leak; caught
  // by E2E 82). Re-enabling safely requires write-path invalidation (a per-tenant search-index version
  // bumped inside the DocumentsService projection and folded into resultCacheKey) — not settings-only
  // invalidation, which (like content hooks) misses admin/media writes. Operators may opt in (>0) once
  // they accept the staleness window.
  cacheTtlSeconds: 0,
  searchableTypes: [],
}

export const FTS_SETTINGS_KEY = 'fts-search:settings:v1'

export async function getFtsSettings(kv?: KVNamespace): Promise<FtsSettings> {
  if (!kv) return { ...DEFAULT_FTS_SETTINGS }
  try {
    const raw = await kv.get(FTS_SETTINGS_KEY)
    if (!raw) return { ...DEFAULT_FTS_SETTINGS }
    return { ...DEFAULT_FTS_SETTINGS, ...(JSON.parse(raw) as Partial<FtsSettings>) }
  } catch {
    return { ...DEFAULT_FTS_SETTINGS }
  }
}

export async function saveFtsSettings(kv: KVNamespace, partial: Partial<FtsSettings>): Promise<FtsSettings> {
  const next = { ...(await getFtsSettings(kv)), ...partial }
  await kv.put(FTS_SETTINGS_KEY, JSON.stringify(next))
  return next
}
