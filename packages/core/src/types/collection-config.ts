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
  | 'lexical'
  | 'markdown'
  | 'mdxeditor'
  | 'easymde'
  | 'quill'
  | 'tinymce'
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
  | 'user'

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
  itemTitle?: string
  properties?: Record<string, FieldConfig>
  blocks?: BlockDefinitions
  discriminator?: string
  collapsed?: boolean
  objectLayout?: 'nested' | 'flat'

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
   * e.g., 'blog_post', 'products', 'team_members'
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
   * If true, this is an internal system collection hidden by default in the admin UI
   * Default: false
   */
  internal?: boolean

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

  /**
   * Optional URL-safe slug for the API base route.
   * Defaults to the collection name if not set.
   * e.g., slug: 'blog-posts' → GET /api/blog-posts
   */
  slug?: string

  /**
   * Opt this collection into version history. Default false.
   * When true: each saveDraft creates a new version row; the versioning-plugin
   * surfaces history/restore UI on the edit form.
   * When false: saveDraft updates the single draft row in place (no history).
   */
  versioning?: boolean

  /**
   * Optional per-collection cache config.
   * Overrides the cache plugin's default TTL for this collection's API responses.
   * `enabled: false` disables caching for the collection entirely.
   * `ttl` is in seconds.
   */
  cache?: {
    enabled?: boolean
    ttl?: number
  }

  /**
   * Per-collection access control. Maps principal keys to allowed permissions.
   *
   * Without this property the collection defaults to **deny** for public access
   * (only `admin` and `editor` get grants). To make content publicly readable,
   * explicitly opt in:
   *
   * ```ts
   * access: {
   *   public: ['read'],
   * }
   * ```
   *
   * Keys are principal identifiers matched during ACL resolution:
   * - `'public'` — unauthenticated visitors
   * - `'admin'`, `'editor'`, `'viewer'`, or any custom RBAC role name
   *
   * Values are arrays of permissions: `'read'`, `'create'`, `'update'`,
   * `'delete'`, `'publish'`, `'manage'`.
   *
   * When provided, these entries are **merged on top of** the built-in defaults
   * (`admin` and `editor` grants). To revoke a default grant, set the key to
   * an empty array (e.g. `editor: []`).
   */
  access?: Record<string, ('read' | 'create' | 'update' | 'delete' | 'publish' | 'manage')[]>
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
