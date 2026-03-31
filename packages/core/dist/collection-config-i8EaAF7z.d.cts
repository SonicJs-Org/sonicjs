/**
 * Collection Configuration Types
 *
 * These types define the structure for collection configuration files.
 * Collections can be defined in TypeScript/JSON files and synced to the database.
 */
type FieldType = 'string' | 'number' | 'boolean' | 'date' | 'datetime' | 'email' | 'url' | 'richtext' | 'markdown' | 'json' | 'array' | 'object' | 'reference' | 'media' | 'select' | 'multiselect' | 'checkbox' | 'radio' | 'textarea' | 'slug' | 'color' | 'file' | 'tinymce' | 'quill' | 'easymde';
interface BlockDefinition {
    label?: string;
    description?: string;
    properties: Record<string, FieldConfig>;
}
type BlockDefinitions = Record<string, BlockDefinition>;
interface FieldConfig {
    type: FieldType;
    title?: string;
    description?: string;
    required?: boolean;
    default?: any;
    placeholder?: string;
    helpText?: string;
    min?: number;
    max?: number;
    minLength?: number;
    maxLength?: number;
    pattern?: string;
    enum?: string[];
    enumLabels?: string[];
    collection?: string | string[];
    items?: FieldConfig;
    itemTitle?: string;
    properties?: Record<string, FieldConfig>;
    blocks?: BlockDefinitions;
    discriminator?: string;
    format?: string;
    widget?: string;
    dependsOn?: string;
    showWhen?: any;
}
interface CollectionSchema {
    type: 'object';
    properties: Record<string, FieldConfig>;
    required?: string[];
}
interface CollectionConfig {
    /**
     * Unique machine name for the collection (lowercase, underscores)
     * e.g., 'blog_posts', 'products', 'team_members'
     */
    name: string;
    /**
     * Human-readable display name
     * e.g., 'Blog Posts', 'Products', 'Team Members'
     */
    displayName: string;
    /**
     * Optional description of the collection
     */
    description?: string;
    /**
     * JSON schema definition for the collection's content structure
     */
    schema: CollectionSchema;
    /**
     * If true, this collection is managed by config files and cannot be edited in the UI
     * Default: true for config-based collections
     */
    managed?: boolean;
    /**
     * If true, the collection is active and available for use
     * Default: true
     */
    isActive?: boolean;
    /**
     * Optional icon name for the collection (used in admin UI)
     */
    icon?: string;
    /**
     * Optional color for the collection (hex code)
     */
    color?: string;
    /**
     * Optional default sort field
     */
    defaultSort?: string;
    /**
     * Optional default sort order
     */
    defaultSortOrder?: 'asc' | 'desc';
    /**
     * Optional fields to show in list view
     */
    listFields?: string[];
    /**
     * Optional search fields
     */
    searchFields?: string[];
    /**
     * Optional metadata
     */
    metadata?: Record<string, any>;
}
interface CollectionConfigModule {
    default: CollectionConfig;
}
/**
 * Result of syncing a collection
 */
interface CollectionSyncResult {
    name: string;
    status: 'created' | 'updated' | 'unchanged' | 'error';
    message?: string;
    error?: string;
}

export type { BlockDefinition as B, CollectionSchema as C, FieldType as F, FieldConfig as a, BlockDefinitions as b, CollectionConfig as c, CollectionConfigModule as d, CollectionSyncResult as e };
