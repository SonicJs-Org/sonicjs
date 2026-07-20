/**
 * Plugin Middleware
 *
 * Provides middleware functions for checking plugin status and enforcing plugin requirements
 */

import type { D1Database } from '@cloudflare/workers-types'

// Per-DB cache: avoids a D1 round-trip on every API request. Keyed by the binding
// object (WeakMap), not module-level: one isolate reuses one env.DB, so the request-path
// dedup is fully preserved — while a DIFFERENT database (each unit test's fresh mock/
// in-memory DB) gets its own map instead of another DB's cached statuses.
// Invalidation is a generation stamp (a WeakMap can't be enumerated): bumping it lazily
// discards every DB's map on next read. Activate/deactivate is rare; the refill is one
// D1 read per plugin.
let _pluginStatusGen = 0
const _pluginStatusCaches = new WeakMap<D1Database, { gen: number; map: Map<string, boolean> }>()

export function invalidatePluginStatusCache(_pluginId?: string): void {
  // Per-plugin granularity can't reach into per-DB maps through a WeakMap; a full
  // generation bump is always correct and costs at most one re-read per plugin.
  _pluginStatusGen++
}

/**
 * Check if a plugin is active. Result is cached per isolate to avoid a D1
 * round-trip on every API request. Call invalidatePluginStatusCache() after
 * activate/deactivate operations.
 */
export async function isPluginActive(db: D1Database, pluginId: string): Promise<boolean> {
  let entry = _pluginStatusCaches.get(db)
  if (!entry || entry.gen !== _pluginStatusGen) {
    entry = { gen: _pluginStatusGen, map: new Map() }
    _pluginStatusCaches.set(db, entry)
  }
  if (entry.map.has(pluginId)) {
    return entry.map.get(pluginId)!
  }
  try {
    // documents table is the authoritative source — PluginService writes here on install/activate.
    // Sidebar nav uses the same query pattern; plugins table is unreliable (may not exist).
    const docResult = await db
      .prepare(
        `SELECT json_extract(data, '$.status') as status FROM documents
         WHERE slug = ? AND type_id = 'plugin' AND tenant_id = 'default'
           AND is_current_draft = 1 AND deleted_at IS NULL`
      )
      .bind(pluginId)
      .first()
    const active = (docResult as any)?.status === 'active'
    entry.map.set(pluginId, active)
    return active
  } catch (error) {
    console.error(`[isPluginActive] Error checking plugin status for ${pluginId}:`, error)
    return false
  }
}

/**
 * Middleware to require a plugin to be active
 * Throws an error if the plugin is not active
 * @param db - The D1 database instance
 * @param pluginId - The plugin ID to check
 * @throws Error if plugin is not active
 */
export async function requireActivePlugin(db: D1Database, pluginId: string): Promise<void> {
  const isActive = await isPluginActive(db, pluginId)
  if (!isActive) {
    throw new Error(`Plugin '${pluginId}' is required but is not active`)
  }
}

/**
 * Middleware to require multiple plugins to be active
 * Throws an error if any plugin is not active
 * @param db - The D1 database instance
 * @param pluginIds - Array of plugin IDs to check
 * @throws Error if any plugin is not active
 */
export async function requireActivePlugins(db: D1Database, pluginIds: string[]): Promise<void> {
  for (const pluginId of pluginIds) {
    await requireActivePlugin(db, pluginId)
  }
}

/**
 * Get all active plugins
 * @param db - The D1 database instance
 * @returns Promise<any[]> - Array of active plugin records
 */
export async function getActivePlugins(db: D1Database): Promise<any[]> {
  try {
    const { results } = await db
      .prepare(
        `SELECT slug as id, json_extract(data, '$.status') as status, data FROM documents
         WHERE type_id = 'plugin' AND tenant_id = 'default'
           AND q_plugin_status = 'active' AND is_current_draft = 1 AND deleted_at IS NULL`
      )
      .all()

    return results || []
  } catch (error) {
    console.error('[getActivePlugins] Error fetching active plugins:', error)
    return []
  }
}
