/**
 * Collection Configuration Types
 *
 * These types define the structure for collection configuration files.
 * Collections can be defined in TypeScript/JSON files and synced to the database.
 */

export type FieldType =
  | 'string'
  | 'number'
  | 'boolean'
  | 'date'
  | 'datetime'
  | 'email'
  | 'url'
  | 'richtext'
  | 'markdown'
  | 'json'
  | 'array'
  | 'object'
  | 'reference'
  | 'media'
  | 'select'
  | 'multiselect'
  | 'checkbox'
  | 'radio'
  | 'textarea'
  | 'slug'
  | 'color'
  | 'file'
  | 'tinymce'
  | 'quill'
  | 'easymde'

export interface BlockDefinition {
  label?: string
  description?: string
  properties: Record<string, FieldConfig>
}

export type BlockDefinitions = Record<string, BlockDefinition>

export interface FieldConfig {
  type: FieldType
  title?: string
  description?: string
  required?: boolean
  default?: any
  placeholder?: string
  helpText?: string

  // Validation
  min?: number
  max?: number
  minLength?: number
  maxLength?: number
  pattern?: string

  // Select/Radio/Multiselect options
  enum?: string[]
  enumLabels?: string[]

  // Reference field
  collection?: string | string[]

  // Array/Object fields
  items?: FieldConfig
  properties?: Record<string, FieldConfig>
  blocks?: BlockDefinitions
  discriminator?: string

  // UI hints
  format?: string
  widget?: string

  // Conditional display
  dependsOn?: string
  showWhen?: any
}

export interface CollectionSchema {
  type: 'object'
  properties: Record<string, FieldConfig>
  required?: string[]
}

export interface CollectionConfig {
  /**
   * Unique machine name for the collection (lowercase, underscores)
   * e.g., 'blog_posts', 'products', 'team_members'
   */
  name: string

  /**
   * Human-readable display name
   * e.g., 'Blog Posts', 'Products', 'Team Members'
   */
  displayName: string

  /**
   * Optional description of the collection
   */
  description?: string

  /**
   * JSON schema definition for the collection's content structure
   */
  schema: CollectionSchema

  /**
   * If true, this collection is managed by config files and cannot be edited in the UI
   * Default: true for config-based collections
   */
  managed?: boolean

  /**
   * If true, the collection is active and available for use
   * Default: true
   */
  isActive?: boolean

  /**
   * Optional icon name for the collection (used in admin UI)
   */
  icon?: string

  /**
   * Optional color for the collection (hex code)
   */
  color?: string

  /**
   * Optional default sort field
   */
  defaultSort?: string

  /**
   * Optional default sort order
   */
  defaultSortOrder?: 'asc' | 'desc'

  /**
   * Optional fields to show in list view
   */
  listFields?: string[]

  /**
   * Optional search fields
   */
  searchFields?: string[]

  /**
   * Optional metadata
   */
  metadata?: Record<string, any>
}

export interface CollectionConfigModule {
  default: CollectionConfig
}

/**
 * Result of syncing a collection
 */
export interface CollectionSyncResult {
  name: string
  status: 'created' | 'updated' | 'unchanged' | 'error'
  message?: string
  error?: string
}
