/**
 * Collection Sync Service
 *
 * Syncs collection configurations from code to the database.
 * Handles create, update, and validation of config-managed collections.
 */

import { CollectionConfig, CollectionSyncResult } from '../types/collection-config'
import { loadCollectionConfigs, validateCollectionConfig } from './collection-loader'

/**
 * Sync all collection configurations to the database
 */
export async function syncCollections(db: D1Database): Promise<CollectionSyncResult[]> {
  console.log('🔄 Starting collection sync...')

  const results: CollectionSyncResult[] = []
  const configs = await loadCollectionConfigs()

  if (configs.length === 0) {
    console.log('⚠️  No collection configurations found')
    return results
  }

  for (const config of configs) {
    const result = await syncCollection(db, config)
    results.push(result)
  }

  const created = results.filter(r => r.status === 'created').length
  const updated = results.filter(r => r.status === 'updated').length
  const unchanged = results.filter(r => r.status === 'unchanged').length
  const errors = results.filter(r => r.status === 'error').length

  console.log(`✅ Collection sync complete: ${created} created, ${updated} updated, ${unchanged} unchanged, ${errors} errors`)

  return results
}

/**
 * Sync a single collection configuration to the database
 */
export async function syncCollection(db: D1Database, config: CollectionConfig): Promise<CollectionSyncResult> {
  try {
    // Validate config
    const validation = validateCollectionConfig(config)
    if (!validation.valid) {
      return {
        name: config.name,
        status: 'error',
        error: `Validation failed: ${validation.errors.join(', ')}`
      }
    }

    // Check if collection exists
    const existingStmt = db.prepare('SELECT * FROM collections WHERE name = ?')
    const existing = await existingStmt.bind(config.name).first() as any

    const now = Date.now()
    const collectionId = existing?.id || `col-${config.name}-${crypto.randomUUID().slice(0, 8)}`

    // Prepare collection data
    const schemaJson = JSON.stringify(config.schema)
    const isActive = config.isActive !== false ? 1 : 0
    const managed = config.managed !== false ? 1 : 0
    const sourceType = 'code'

    if (!existing) {
      // Create new collection
      const insertStmt = db.prepare(`
        INSERT INTO collections (id, name, display_name, description, schema, is_active, managed, source_type, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)

      await insertStmt.bind(
        collectionId,
        config.name,
        config.displayName,
        config.description || null,
        schemaJson,
        isActive,
        managed,
        sourceType,
        now,
        now
      ).run()

      console.log(`  ✓ Created collection: ${config.name}`)

      return {
        name: config.name,
        status: 'created',
        message: `Created collection "${config.displayName}"`
      }
    } else {
      // Check if update is needed
      const existingSchema = existing.schema ? JSON.stringify(existing.schema) : '{}'
      const existingDisplayName = existing.display_name
      const existingDescription = existing.description
      const existingIsActive = existing.is_active
      const existingManaged = existing.managed
      const existingSourceType = existing.source_type

      const needsUpdate =
        schemaJson !== existingSchema ||
        config.displayName !== existingDisplayName ||
        (config.description || null) !== existingDescription ||
        isActive !== existingIsActive ||
        managed !== existingManaged ||
        sourceType !== existingSourceType

      if (!needsUpdate) {
        return {
          name: config.name,
          status: 'unchanged',
          message: `Collection "${config.displayName}" is up to date`
        }
      }

      // Update existing collection
      const updateStmt = db.prepare(`
        UPDATE collections
        SET display_name = ?, description = ?, schema = ?, is_active = ?, managed = ?, source_type = ?, source_id = NULL, updated_at = ?
        WHERE name = ?
      `)

      await updateStmt.bind(
        config.displayName,
        config.description || null,
        schemaJson,
        isActive,
        managed,
        sourceType,
        now,
        config.name
      ).run()

      console.log(`  ✓ Updated collection: ${config.name}`)

      return {
        name: config.name,
        status: 'updated',
        message: `Updated collection "${config.displayName}"`
      }
    }
  } catch (error) {
    console.error(`  ✗ Error syncing collection ${config.name}:`, error)

    return {
      name: config.name,
      status: 'error',
      error: error instanceof Error ? error.message : 'Unknown error'
    }
  }
}

/**
 * Check if a collection is managed by config
 */
export async function isCollectionManaged(db: D1Database, collectionName: string): Promise<boolean> {
  try {
    const stmt = db.prepare('SELECT managed FROM collections WHERE name = ?')
    const result = await stmt.bind(collectionName).first() as any

    return result?.managed === 1
  } catch (error) {
    console.error(`Error checking if collection is managed:`, error)
    return false
  }
}

/**
 * Get all managed collections from database
 */
export async function getManagedCollections(db: D1Database): Promise<string[]> {
  try {
    const stmt = db.prepare('SELECT name FROM collections WHERE managed = 1')
    const { results } = await stmt.all()

    return (results || []).map((row: any) => row.name)
  } catch (error) {
    console.error('Error getting managed collections:', error)
    return []
  }
}

/**
 * Remove collections that are no longer in config files
 * (Only removes managed collections that aren't in the config)
 */
export async function cleanupRemovedCollections(db: D1Database): Promise<string[]> {
  try {
    const configs = await loadCollectionConfigs()
    const configNames = new Set(configs.map(c => c.name))
    const managedCollections = await getManagedCollections(db)
    const removed: string[] = []

    for (const managedName of managedCollections) {
      if (!configNames.has(managedName)) {
        // This managed collection no longer has a config file
        // Mark as inactive instead of deleting (safer)
        const updateStmt = db.prepare(`
          UPDATE collections
          SET is_active = 0, updated_at = ?
          WHERE name = ? AND managed = 1
        `)

        await updateStmt.bind(Date.now(), managedName).run()
        removed.push(managedName)
        console.log(`  ⚠️  Deactivated removed collection: ${managedName}`)
      }
    }

    return removed
  } catch (error) {
    console.error('Error cleaning up removed collections:', error)
    return []
  }
}

/**
 * Full sync: sync all configs and cleanup removed
 */
export async function fullCollectionSync(db: D1Database): Promise<{
  results: CollectionSyncResult[]
  removed: string[]
}> {
  const results = await syncCollections(db)
  const removed = await cleanupRemovedCollections(db)

  return { results, removed }
}
