/**
 * CollectionRegistry — in-memory registry of code-defined collections.
 *
 * Replaces the DB `collections` table as the source of truth for collection
 * metadata. Populated once at bootstrap from `loadCollectionConfigs()` (which
 * reads code-registered collections). Code-defined IDs are stable across envs:
 * `collection.id === collection.name`.
 */

import { CollectionConfig } from '../types/collection-config'

export interface CollectionRecord extends CollectionConfig {
  /** Stable id = collection.name. Always equals `name` for code-defined collections. */
  id: string
}

export class CollectionRegistry {
  private byName = new Map<string, CollectionRecord>()
  private bySlug = new Map<string, CollectionRecord>()

  /**
   * Replace the registry contents with the given configs. Idempotent —
   * calling with the same configs twice yields the same state.
   */
  register(configs: CollectionConfig[]): void {
    this.byName.clear()
    this.bySlug.clear()
    for (const config of configs) {
      if (!config.name) continue
      const record: CollectionRecord = {
        ...config,
        id: config.name,
        slug: config.slug ?? config.name.replace(/_/g, '-'),
        managed: config.managed !== undefined ? config.managed : true,
        isActive: config.isActive !== undefined ? config.isActive : true,
      }
      this.byName.set(record.name, record)
      this.bySlug.set(record.slug!, record)
    }
  }

  /** All registered collections (including inactive). */
  list(): CollectionRecord[] {
    return Array.from(this.byName.values())
  }

  /** Active collections only. */
  listActive(): CollectionRecord[] {
    return this.list().filter((c) => c.isActive !== false)
  }

  getByName(name: string): CollectionRecord | undefined {
    return this.byName.get(name)
  }

  /** For code-defined collections, id === name. */
  getById(id: string): CollectionRecord | undefined {
    return this.byName.get(id)
  }

  /** Look up by the URL slug (set in CollectionConfig.slug). Falls back to getByName if needed. */
  getBySlug(slug: string): CollectionRecord | undefined {
    return this.bySlug.get(slug)
  }

  /** Resolve a path segment to a record — tries slug first, then name. */
  getBySlugOrName(slugOrName: string): CollectionRecord | undefined {
    return this.bySlug.get(slugOrName) ?? this.byName.get(slugOrName)
  }

  isActive(name: string): boolean {
    const record = this.byName.get(name)
    return record?.isActive !== false && record !== undefined
  }

  size(): number {
    return this.byName.size
  }

  /** Test helper — wipe state. */
  clear(): void {
    this.byName.clear()
    this.bySlug.clear()
  }
}

/**
 * Map a registry record to the snake_case shape historically returned by
 * `SELECT * FROM collections`. Used by API routes during the consumer
 * migration so downstream clients see no schema drift.
 */
export interface CollectionRowShape {
  id: string
  name: string
  display_name: string
  description: string | null
  schema: any
  is_active: number
  managed: number
  source_type: string
  source_id: string | null
  created_at: number
  updated_at: number
}

export function collectionRecordToRow(record: CollectionRecord): CollectionRowShape {
  return {
    id: record.id,
    name: record.name,
    display_name: record.displayName,
    description: record.description ?? null,
    schema: record.schema,
    is_active: record.isActive === false ? 0 : 1,
    managed: record.managed === false ? 0 : 1,
    source_type: 'code',
    source_id: null,
    created_at: 0,
    updated_at: 0,
  }
}

// Module-level singleton. Bootstrap populates; consumers read.
let instance: CollectionRegistry | null = null

export function getCollectionRegistry(): CollectionRegistry {
  if (!instance) {
    instance = new CollectionRegistry()
  }
  return instance
}

/** Test helper — reset singleton between tests. */
export function resetCollectionRegistry(): void {
  instance = null
}
