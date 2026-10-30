/**
 * Convert a SonicJS collection schema (FieldConfig graph) into JSON Schema for MCP
 * tool input definitions.
 *
 * Collections are `FieldConfig[]`-shaped (`types/collection-config.ts`), not Zod, so
 * there is nothing to feed `zod-to-json-schema`. A collection's `schema` is already
 * close to JSON Schema (`{ type:'object', properties, required }`); this maps each
 * field's SonicJS `FieldType` to its JSON Schema equivalent and, for write tools,
 * strips server-managed system fields.
 */

import type { CollectionSchema, FieldConfig } from '../../../../types/collection-config'

/** Fields the server sets — never accepted from a create/update tool payload. */
const SYSTEM_FIELDS = new Set([
  'id', 'root_id', 'rootId',
  'created_at', 'createdAt',
  'updated_at', 'updatedAt',
  'version_number', 'versionNumber',
])

export type JsonSchemaNode = Record<string, unknown>

/** Map a single field to a JSON Schema node. */
export function fieldToJsonSchema(field: FieldConfig): JsonSchemaNode {
  const base: JsonSchemaNode = {}
  if (field.title) base.title = field.title
  if (field.description) base.description = field.description

  switch (field.type) {
    case 'number':
      return {
        ...base,
        type: 'number',
        ...(field.min != null ? { minimum: field.min } : {}),
        ...(field.max != null ? { maximum: field.max } : {}),
      }

    case 'boolean':
    case 'checkbox':
      return { ...base, type: 'boolean' }

    case 'date':
    case 'datetime':
      return { ...base, type: 'string', format: 'date-time' }

    case 'select':
    case 'radio':
      return { ...base, type: 'string', ...(field.enum ? { enum: field.enum } : {}) }

    case 'multiselect':
      return {
        ...base,
        type: 'array',
        items: { type: 'string', ...(field.enum ? { enum: field.enum } : {}) },
      }

    case 'array':
      return {
        ...base,
        type: 'array',
        items: field.items ? fieldToJsonSchema(field.items) : {},
      }

    case 'object':
      return {
        ...base,
        type: 'object',
        ...(field.properties ? { properties: mapProperties(field.properties) } : {}),
      }

    case 'json':
      // Free-form value — no constraint beyond "present".
      return { ...base }

    // string-like: string, slug, email, url, richtext, markdown, textarea, editors,
    // reference, media, color, file, user
    default: {
      const node: JsonSchemaNode = { ...base, type: 'string' }
      if (field.minLength != null) node.minLength = field.minLength
      if (field.maxLength != null) node.maxLength = field.maxLength
      if (field.pattern) node.pattern = field.pattern
      if (field.format) node.format = field.format
      return node
    }
  }
}

function mapProperties(props: Record<string, FieldConfig>): Record<string, JsonSchemaNode> {
  const out: Record<string, JsonSchemaNode> = {}
  for (const [name, field] of Object.entries(props)) {
    out[name] = fieldToJsonSchema(field)
  }
  return out
}

export interface CollectionSchemaOptions {
  /** Strip system-managed fields (for create/update tool inputs). */
  forWrite?: boolean
  /** Field names to omit entirely. */
  redactFields?: string[]
}

/**
 * Convert a whole collection schema to a JSON Schema object. `required` is the union
 * of each field's `required` flag and the schema-level `required[]`.
 */
export function collectionToJsonSchema(
  schema: CollectionSchema,
  opts: CollectionSchemaOptions = {},
): JsonSchemaNode {
  const properties: Record<string, JsonSchemaNode> = {}
  const required: string[] = []
  const redact = new Set(opts.redactFields ?? [])
  const schemaRequired = new Set(schema.required ?? [])

  for (const [name, field] of Object.entries(schema.properties ?? {})) {
    if (redact.has(name)) continue
    if (opts.forWrite && SYSTEM_FIELDS.has(name)) continue
    properties[name] = fieldToJsonSchema(field)
    if (field.required || schemaRequired.has(name)) required.push(name)
  }

  return { type: 'object', properties, ...(required.length ? { required } : {}) }
}
