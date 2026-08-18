// views-plugin/services/view-cache.ts

import type { KVNamespace, D1Database } from '@cloudflare/workers-types'
import type { TypedHooks } from '../../../hooks/typed-hooks'

const VIEW_CACHE_PREFIX = 'view:'
// Disjoint keyspace for the public embed HTML. `buildKey` only ever emits
// `view:`, so the `/api/views/:name` path (whose key is built from
// attacker-controlled query params) can NEVER write or read a `viewembed:` key —
// the two security contexts cannot collide. This is what closes the embed
// column-leak.
const VIEW_EMBED_PREFIX = 'viewembed:'
const DEFAULT_TTL_SECONDS = 300 // 5 minutes

/**
 * A small, synchronous string fingerprint (FNV-1a, 32-bit) over a display's
 * serialized config. Baked into the embed cache key so a re-publish to a
 * different column whitelist changes the key — old, wider-projection entries
 * become unreachable for new requests immediately (defense-in-depth for the
 * PR-C1 whitelist guarantee). NOT a crypto hash (no async `crypto.subtle`).
 */
export function fingerprintConfig(serialized: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < serialized.length; i++) {
    h ^= serialized.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return (h >>> 0).toString(36)
}

// ─────────────────────────────────────────────────────────────────────────
// ViewCacheService — KV-backed cache for view query results
// ─────────────────────────────────────────────────────────────────────────

export class ViewCacheService {
  constructor(
    private readonly kv: KVNamespace,
    private readonly ttlSeconds: number = DEFAULT_TTL_SECONDS
  ) {}

  /**
   * Build a cache key from tenant + view name + query params. Tenant is baked into every
   * key (not just an outer filter) because `name` is now per-tenant-unique, not global —
   * two tenants can legally have a view named the same thing, and without the tenant
   * segment their cached responses would collide and leak across tenants.
   */
  static buildKey(tenantId: string, viewName: string, params: Record<string, string>): string {
    const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&')
    return `${VIEW_CACHE_PREFIX}${tenantId}:${viewName}:${sorted}`
  }

  async get(tenantId: string, viewName: string, params: Record<string, string>): Promise<string | null> {
    const key = ViewCacheService.buildKey(tenantId, viewName, params)
    return this.kv.get(key)
  }

  async set(tenantId: string, viewName: string, params: Record<string, string>, value: string): Promise<void> {
    const key = ViewCacheService.buildKey(tenantId, viewName, params)
    await this.kv.put(key, value, { expirationTtl: this.ttlSeconds })
  }

  /** Invalidate all cached entries for one tenant's view name (the `/api` keyspace). */
  async invalidateView(tenantId: string, viewName: string): Promise<void> {
    const prefix = `${VIEW_CACHE_PREFIX}${tenantId}:${viewName}:`
    const listed = await this.kv.list({ prefix })
    if (listed.keys.length > 0) {
      await Promise.all(listed.keys.map(k => this.kv.delete(k.name)))
    }
  }

  // ── Public embed keyspace (`viewembed:<tenant>:<path>:…`) — disjoint from `view:`. ──

  /**
   * Key the embed by tenant + its public `path` (the route param) + a config fingerprint.
   * Tenant-scoped for the same reason as buildKey — `path` is now per-tenant-unique, so two
   * tenants' embeds at the same path must not share a cache entry.
   */
  static buildEmbedKey(tenantId: string, path: string, cfgHash: string, page: number): string {
    return `${VIEW_EMBED_PREFIX}${tenantId}:${path}:cfg=${cfgHash}:p=${page}`
  }

  async getEmbed(tenantId: string, path: string, cfgHash: string, page: number): Promise<string | null> {
    return this.kv.get(ViewCacheService.buildEmbedKey(tenantId, path, cfgHash, page))
  }

  async setEmbed(tenantId: string, path: string, cfgHash: string, page: number, html: string): Promise<void> {
    await this.kv.put(ViewCacheService.buildEmbedKey(tenantId, path, cfgHash, page), html, {
      expirationTtl: this.ttlSeconds,
    })
  }

  /** Invalidate every cached embed page for one tenant's published `path`. */
  async invalidateEmbed(tenantId: string, path: string): Promise<void> {
    const prefix = `${VIEW_EMBED_PREFIX}${tenantId}:${path}:`
    const listed = await this.kv.list({ prefix })
    if (listed.keys.length > 0) {
      await Promise.all(listed.keys.map(k => this.kv.delete(k.name)))
    }
  }

  /**
   * Invalidate all views (both `/api` and embed keyspaces) for a collection, across
   * whichever tenants happen to have a view over it. The content-change hook that drives
   * this has no tenant field on its payload (a pre-existing, core-level limitation — content
   * hooks aren't tenant-scoped anywhere in the app today, not something introduced or fixed
   * here), so tenant isn't known going in; each matching row's OWN `tenant_id` is read back
   * from the query instead, so every invalidation is still correctly scoped to the tenant
   * that actually owns that view/embed — just discovered per-row rather than passed in.
   */
  async invalidateByCollection(db: D1Database, collectionId: string): Promise<void> {
    // The content hooks carry the collection NAME; views store the document_type ID.
    // id == name for every code-registered collection, but a DB-created type may differ —
    // resolve the id by name and match either, so its views don't ride the 300s TTL
    // instead of the hook (polish item 5 from the 2026-07-04 review).
    const ids = [collectionId]
    const byName = await db
      .prepare(`SELECT id FROM document_types WHERE name = ?`)
      .bind(collectionId)
      .first<{ id: string }>()
    if (byName && byName.id !== collectionId) ids.push(byName.id)
    const placeholders = ids.map(() => '?').join(', ')

    const { results } = await db
      .prepare(`SELECT tenant_id, name FROM views WHERE collection_id IN (${placeholders}) AND status = 'active'`)
      .bind(...ids)
      .all<{ tenant_id: string; name: string }>()

    if (results && results.length > 0) {
      await Promise.all(results.map((r) => this.invalidateView(r.tenant_id, r.name)))
    }

    // Also clear the published embed caches for those views — the embed lives in a
    // separate keyspace `invalidateView` does not touch, so without this a content
    // change would refresh `/api` but leave `/v/:path` stale.
    const { results: embeds } = await db
      .prepare(
        `SELECT d.tenant_id, d.path FROM view_displays d
           JOIN views v ON d.view_id = v.id
          WHERE v.collection_id IN (${placeholders}) AND v.status = 'active'
            AND d.path IS NOT NULL AND d.is_public = 1`
      )
      .bind(...ids)
      .all<{ tenant_id: string; path: string }>()

    if (embeds && embeds.length > 0) {
      await Promise.all(embeds.map((e) => this.invalidateEmbed(e.tenant_id, e.path)))
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Hook registration — invalidate view cache on content changes
// ─────────────────────────────────────────────────────────────────────────

/**
 * Wire content-change invalidation onto the typed hook facade (call from the plugin's
 * `onBoot(ctx)` with `ctx.hooks`). The payload's `collection` is the content-type slug;
 * views store the document-type id as `collection_id`, and for code-defined collections
 * the registry id == name — so the slug keys the invalidation directly.
 */
export function registerViewCacheHooks(
  hooks: TypedHooks,
  db: D1Database,
  kv: KVNamespace | undefined
): void {
  if (!kv) return // No KV binding → no caching

  const cache = new ViewCacheService(kv)

  const invalidate = (collection: string): void => {
    // Fire-and-forget: cache invalidation must never fail or slow the content write.
    void cache.invalidateByCollection(db, collection).catch((err: unknown) => {
      console.warn('[ViewCache] Invalidation failed:', err)
    })
  }

  hooks.on('content:after:create', (payload) => { invalidate(payload.collection) })
  hooks.on('content:after:update', (payload) => { invalidate(payload.collection) })
  hooks.on('content:after:delete', (payload) => { invalidate(payload.collection) })
}
