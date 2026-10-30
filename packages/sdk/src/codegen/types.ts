/**
 * Minimal local types matching @sonicjs-cms/core's CollectionConfig/FieldConfig shapes.
 * Defined locally so the SDK runtime has zero dependency on core — no transitive workers-types
 * bleed-through when type-checking the SDK in isolation.
 */

export type SdkFieldType =
  | 'string' | 'number' | 'boolean'
  | 'date' | 'datetime'
  | 'email' | 'url' | 'richtext' | 'lexical' | 'markdown' | 'textarea'
  | 'json' | 'array' | 'object'
  | 'reference' | 'media' | 'file' | 'user'
  | 'select' | 'multiselect' | 'checkbox' | 'radio'
  | 'slug' | 'color'

export interface SdkFieldConfig {
  type: SdkFieldType | string
  required?: boolean
  enum?: unknown[]
  items?: SdkFieldConfig
  properties?: Record<string, SdkFieldConfig>
  collection?: string
  [k: string]: unknown
}

export interface SdkCollectionSchema {
  type?: string
  properties?: Record<string, SdkFieldConfig>
  required?: string[]
}

export interface SdkCollectionConfig {
  name: string
  displayName?: string
  slug?: string
  schema?: SdkCollectionSchema
  settings?: Record<string, unknown>
  [k: string]: unknown
}
