/**
 * Collection Loader Service
 *
 * Loads collection configuration files from the collections directory.
 * Supports both development (reading from filesystem) and production (bundled).
 */

import type { D1Database } from '@cloudflare/workers-types'
import { CollectionConfig, CollectionConfigModule } from '../types/collection-config'
import { getCollectionRegistry } from './collection-registry'

export interface VisibleCollection {
  name: string
  displayName: string
}

/** True when a code-registry collection should be hidden from user-facing menus. */
export function isCodeCollectionInternal(cfg: { internal?: boolean }): boolean {
  return cfg.internal === true
}

/** True when a document_types DB row should be hidden from user-facing menus. */
export function isDbDocTypeInternal(source?: string | null): boolean {
  return source === 'system' || source === 'plugin'
}

/**
 * Returns collections visible to users (non-internal) for UI menus like "New Content".
 * Canonical filtering logic shared with /admin/collections:
 *   - Code registry: cfg.internal !== true
 *   - DB document_types: source is not 'system' or 'plugin'
 * Code registry wins on name collisions.
 */
export async function getVisibleCollections(db: D1Database): Promise<VisibleCollection[]> {
  const codeRegistry = getCollectionRegistry().list()
  const codeMap = new Map<string, VisibleCollection>()
  for (const cfg of codeRegistry) {
    if (!isCodeCollectionInternal(cfg)) {
      codeMap.set(cfg.name, { name: cfg.name, displayName: cfg.displayName })
    }
  }

  let dbRows: any[] = []
  try {
    const { results } = await db.prepare(
      "SELECT name, display_name, source FROM document_types WHERE is_active = 1 ORDER BY display_name"
    ).all()
    dbRows = results ?? []
  } catch {
    // document_types may not exist in early dev
  }

  const merged = new Map<string, VisibleCollection>(codeMap)
  for (const row of dbRows) {
    if (!isDbDocTypeInternal(row.source) && !merged.has(row.name)) {
      merged.set(row.name, { name: String(row.name), displayName: String(row.display_name) })
    }
  }

  return Array.from(merged.values())
}

// Global registry for externally registered collections
const registeredCollections: CollectionConfig[] = []

/**
 * Register collections from the application code
 * This should be called before creating the app
 */
export function registerCollections(collections: CollectionConfig[]): void {
  for (const config of collections) {
    // Validate required fields
    if (!config.name || !config.displayName || !config.schema) {
      console.error(`Invalid collection config: missing required fields`, config)
      continue
    }

    // Set defaults
    const normalizedConfig: CollectionConfig = {
      ...config,
      managed: config.managed !== undefined ? config.managed : true,
      isActive: config.isActive !== undefined ? config.isActive : true
    }

    registeredCollections.push(normalizedConfig)
    console.log(`✓ Registered collection: ${config.name}`)
  }
}

/**
 * Load all collection configurations from the collections directory
 */
export async function loadCollectionConfigs(): Promise<CollectionConfig[]> {
  const collections: CollectionConfig[] = [...registeredCollections]

  // Log registered collections summary
  if (registeredCollections.length > 0) {
    console.log(`📦 Found ${registeredCollections.length} registered collection(s) from application`)
  } else {
    console.log(`⚠️  No collections registered. Make sure to call registerCollections() in your app's index.ts`)
    console.log(`   Example: import myCollection from './collections/my-collection.collection'`)
    console.log(`            registerCollections([myCollection])`)
  }

  try {
    // Import all collection files dynamically from core package
    // In production, these will be bundled with the application
    const modules = (import.meta as any).glob?.('../collections/*.collection.ts', { eager: true }) || {}
    let coreCollectionCount = 0

    for (const [path, module] of Object.entries(modules)) {
      try {
        const configModule = module as CollectionConfigModule

        if (!configModule.default) {
          console.warn(`Collection file ${path} does not export a default config`)
          continue
        }

        const config = configModule.default

        // Validate required fields
        if (!config.name || !config.displayName || !config.schema) {
          console.error(`Invalid collection config in ${path}: missing required fields`)
          continue
        }

        // Set defaults
        const normalizedConfig: CollectionConfig = {
          ...config,
          managed: config.managed !== undefined ? config.managed : true,
          isActive: config.isActive !== undefined ? config.isActive : true
        }

        collections.push(normalizedConfig)
        coreCollectionCount++
        console.log(`✓ Loaded core collection: ${config.name}`)
      } catch (error) {
        console.error(`Error loading collection from ${path}:`, error)
      }
    }

    console.log(`📊 Collection summary: ${collections.length} total (${registeredCollections.length} from app, ${coreCollectionCount} from core)`)
    return collections
  } catch (error) {
    console.error('Error loading collection configurations:', error)
    return collections // Return registered collections even if core loading fails
  }
}

/**
 * Load a specific collection configuration by name
 * Note: This function requires implementation in the consuming application
 * as it depends on project-specific collection files
 */
export async function loadCollectionConfig(name: string): Promise<CollectionConfig | null> {
  try {
    // Dynamic imports are not supported in library builds
    // This should be implemented in the consuming application
    console.warn('loadCollectionConfig requires implementation in consuming application')
    return null
  } catch (error) {
    console.error(`Error loading collection ${name}:`, error)
    return null
  }
}

/**
 * Get list of all available collection config file names
 */
export async function getAvailableCollectionNames(): Promise<string[]> {
  try {
    const modules = (import.meta as any).glob?.('../collections/*.collection.ts') || {}
    const names: string[] = []

    for (const path of Object.keys(modules)) {
      // Extract collection name from path
      // e.g., '../collections/blog-posts.collection.ts' -> 'blog-posts'
      const match = path.match(/\/([^/]+)\.collection\.ts$/)
      if (match && match[1]) {
        names.push(match[1])
      }
    }

    return names
  } catch (error) {
    console.error('Error getting collection names:', error)
    return []
  }
}

/**
 * Validate a collection configuration
 */
export function validateCollectionConfig(config: CollectionConfig): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  // Required fields
  if (!config.name) {
    errors.push('Collection name is required')
  } else if (!/^[a-z0-9_-]+$/.test(config.name)) {
    errors.push('Collection name must contain only lowercase letters, numbers, underscores, and hyphens')
  }

  if (!config.displayName) {
    errors.push('Display name is required')
  }

  if (!config.schema) {
    errors.push('Schema is required')
  } else {
    // Validate schema structure
    if (config.schema.type !== 'object') {
      errors.push('Schema type must be "object"')
    }

    if (!config.schema.properties || typeof config.schema.properties !== 'object') {
      errors.push('Schema must have properties')
    }

    // Validate field types
    for (const [fieldName, fieldConfig] of Object.entries(config.schema.properties || {})) {
      if (!fieldConfig.type) {
        errors.push(`Field "${fieldName}" is missing type`)
      }

      // Validate reference fields
      if (fieldConfig.type === 'reference' && !fieldConfig.collection) {
        errors.push(`Reference field "${fieldName}" is missing collection property`)
      }

      const layoutValue = fieldConfig.objectLayout
      if (layoutValue !== undefined) {
        if (fieldConfig.type !== 'object') {
          errors.push(`Field "${fieldName}" uses objectLayout but is not an object field`)
        } else if (!['nested', 'flat'].includes(layoutValue)) {
          errors.push(`Object field "${fieldName}" has invalid objectLayout. Use "nested" or "flat"`)
        }
      }

      // Validate select fields
      if (['select', 'multiselect', 'radio'].includes(fieldConfig.type) && !fieldConfig.enum) {
        errors.push(`Select field "${fieldName}" is missing enum options`)
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  }
}
