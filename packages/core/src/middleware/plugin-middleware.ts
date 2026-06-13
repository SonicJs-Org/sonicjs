/**
 * Plugin Middleware
 *
 * Provides middleware functions for checking plugin status and enforcing plugin requirements
 */

import type { D1Database } from '@cloudflare/workers-types'

/**
 * Check if a plugin is active
 * @param db - The D1 database instance
 * @param pluginId - The plugin ID to check
 * @returns Promise<boolean> - True if the plugin is active, false otherwise
 */
export async function isPluginActive(db: D1Database, pluginId: string): Promise<boolean> {
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
    return (docResult as any)?.status === 'active'
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
