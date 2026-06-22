/**
 * Best-effort KV result cache for lexical search (ported from infowall's search-cache.service).
 *
 * Keyed by a SHA-256 of the normalized query + tenant + paging + filters, so identical queries hit the
 * cache. Caching is fire-and-forget: a KV error never breaks a search. Invalidated wholesale when
 * settings change (relevance/ranking changes invalidate every cached result).
 */
import type { KVNamespace } from '@cloudflare/workers-types'
import type { SearchQuery, SearchResponse } from '../types'

const CACHE_PREFIX = 'fts-search:result:'

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function canonical(query: SearchQuery, tenantId: string): string {
  const f = query.filters ?? {}
  return JSON.stringify({
    q: (query.query ?? '').toLowerCase().trim(),
    t: tenantId,
    m: query.mode,
    l: query.limit ?? null,
    o: query.offset ?? null,
    col: [...(f.collections ?? [])].sort(),
    st: [...(f.status ?? [])].sort(),
  })
}

export async function resultCacheKey(query: SearchQuery, tenantId: string): Promise<string> {
  return CACHE_PREFIX + (await sha256Hex(canonical(query, tenantId))).slice(0, 40)
}

export async function getCachedResult(
  kv: KVNamespace,
  query: SearchQuery,
  tenantId: string,
): Promise<SearchResponse | null> {
  try {
    const raw = await kv.get(await resultCacheKey(query, tenantId))
    return raw ? (JSON.parse(raw) as SearchResponse) : null
  } catch {
    return null
  }
}

export async function putCachedResult(
  kv: KVNamespace,
  query: SearchQuery,
  tenantId: string,
  response: SearchResponse,
  ttlSeconds: number,
): Promise<void> {
  try {
    // KV's minimum expirationTtl is 60s.
    await kv.put(await resultCacheKey(query, tenantId), JSON.stringify(response), {
      expirationTtl: Math.max(60, Math.floor(ttlSeconds)),
    })
  } catch {
    /* best-effort */
  }
}

export async function invalidateResultCache(kv: KVNamespace): Promise<void> {
  try {
    let cursor: string | undefined
    do {
      const list = (await kv.list({ prefix: CACHE_PREFIX, cursor })) as {
        keys: Array<{ name: string }>
        list_complete?: boolean
        cursor?: string
      }
      for (const k of list.keys) await kv.delete(k.name)
      cursor = list.list_complete ? undefined : list.cursor
    } while (cursor)
  } catch {
    /* best-effort */
  }
}
