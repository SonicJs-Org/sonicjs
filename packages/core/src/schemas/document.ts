import { z } from 'zod'

export type Permission = 'read' | 'create' | 'update' | 'delete' | 'publish' | 'manage'
export type PrincipalType = 'user' | 'role' | 'group' | 'public' | 'token'
export type RefStrength = 'strong' | 'weak'
export type QueryableFieldKind = 'scalar' | 'facet' | 'reference'
export type DocumentSource = 'code' | 'plugin' | 'system'
export type DocumentStatus = 'draft' | 'published' | 'archived'

export interface QueryableField {
  name: string
  path?: string
  kind: QueryableFieldKind
  type?: 'text' | 'number' | 'integer' | 'boolean' | 'date'
  column?: string
  refStrength?: RefStrength
}

export interface DocumentTypeSettings {
  baseGrants?: Record<string, Permission[]>
  maxVersionsPerRoot?: number
  pii?: boolean
  /** Hide this type from the admin content list and all-view (e.g. internal system types like 'plugin'). */
  internal?: boolean
  /**
   * Shared/global type: its documents are NOT tenant-scoped — they live in one shared pool and are
   * visible from every tenant. Opt-in (default false). When false, the type is tenant-isolated like
   * everything else. See `effectiveTenantForType` (services/document-request-context.ts).
   */
  global?: boolean
  /**
   * Retain historical version rows for this type. Default false.
   * When false: saveDraft updates the working draft row in place and publish deletes the
   * superseded published row (at most ~2 rows per root, no history accumulation).
   * When true: new row per saveDraft + prune to maxVersionsPerRoot (the versioning-plugin opts types in).
   */
  versioning?: boolean
}

export interface PluginDocumentType {
  id: string
  name: string
  displayName: string
  description?: string
  schema: z.ZodSchema
  settings?: DocumentTypeSettings
  queryableFields?: QueryableField[]
  /** Auth-owned type (users/profiles/rbac). Excluded from content surfaces and public APIs. */
  isAuth?: boolean
}

// DB row types (raw from D1)
export interface DocumentTypeRow {
  id: string
  name: string
  display_name: string
  description: string | null
  schema: string
  queryable_fields: string
  settings: string
  plugin_id: string | null
  source: DocumentSource
  schema_version: number
  is_system: number
  is_active: number
  is_auth: number
  created_at: number
  updated_at: number
}

export interface DocumentRow {
  id: string
  root_id: string
  type_id: string
  type_version: number
  version_of_id: string | null
  version_number: number
  is_current_draft: number
  is_published: number
  status: DocumentStatus
  parent_root_id: string
  slug: string | null
  path: string | null
  title: string | null
  zone: string | null
  sort_order: number
  visible: number
  published_at: number | null
  scheduled_at: number | null
  expires_at: number | null
  deleted_at: number | null
  tenant_id: string
  locale: string
  translation_group_id: string
  data: string
  metadata: string
  owner_id: string | null
  created_by: string | null
  updated_by: string | null
  created_at: number
  updated_at: number
}

export interface DocumentFacetRow {
  id: string
  tenant_id: string
  document_id: string
  root_id: string
  type_id: string
  field_name: string
  ordinal: number
  value_text: string | null
  value_number: number | null
  created_at: number
}

export interface DocumentReferenceRow {
  id: string
  tenant_id: string
  from_root_id: string
  from_document_id: string
  field_name: string
  ordinal: number
  to_root_id: string
  ref_strength: RefStrength
  created_at: number
}

export interface DocumentPermissionRow {
  id: string
  tenant_id: string
  root_id: string
  principal_type: PrincipalType
  principal_id: string
  permission: Permission
  effect: 'allow' | 'deny'
  inherited: number
  created_at: number
  created_by: string | null
}

// Application-level types (parsed from DB rows)
export interface DocumentType {
  id: string
  name: string
  displayName: string
  description: string | null
  schema: Record<string, unknown>
  queryableFields: QueryableField[]
  settings: DocumentTypeSettings
  pluginId: string | null
  source: DocumentSource
  schemaVersion: number
  isSystem: boolean
  isActive: boolean
  isAuth: boolean
  createdAt: number
  updatedAt: number
}

export interface Document {
  id: string
  rootId: string
  typeId: string
  typeVersion: number
  versionOfId: string | null
  versionNumber: number
  isCurrentDraft: boolean
  isPublished: boolean
  status: DocumentStatus
  parentRootId: string
  slug: string | null
  path: string | null
  title: string | null
  zone: string | null
  sortOrder: number
  visible: boolean
  publishedAt: number | null
  scheduledAt: number | null
  expiresAt: number | null
  deletedAt: number | null
  tenantId: string
  locale: string
  translationGroupId: string
  data: Record<string, unknown>
  metadata: Record<string, unknown>
  ownerId: string | null
  createdBy: string | null
  updatedBy: string | null
  createdAt: number
  updatedAt: number
}

export interface PrincipalRef {
  type: PrincipalType
  id: string
}

// Zod validation schemas for API inputs
export const createDocumentSchema = z.object({
  typeId: z.string().min(1),
  tenantId: z.string().default('default'),
  locale: z.string().default('default'),
  parentRootId: z.string().default(''),
  slug: z.string().nullable().optional(),
  title: z.string().nullable().optional(),
  zone: z.string().nullable().optional(),
  sortOrder: z.number().int().default(0),
  visible: z.boolean().default(true),
  scheduledAt: z.number().int().nullable().optional(),
  expiresAt: z.number().int().nullable().optional(),
  data: z.record(z.string(), z.unknown()).default({}),
  metadata: z.record(z.string(), z.unknown()).default({}),
  ownerId: z.string().nullable().optional(),
  publishOnCreate: z.boolean().default(false),
  // Backfill only (D34): preserve the source row's original timestamps (SECONDS). Omitted on normal
  // creates → defaults to "now". `createdAt` also seeds publishedAt for items backfilled as published.
  createdAt: z.number().int().nullable().optional(),
  updatedAt: z.number().int().nullable().optional(),
})

export const updateDocumentSchema = z.object({
  title: z.string().nullable().optional(),
  slug: z.string().nullable().optional(),
  zone: z.string().nullable().optional(),
  sortOrder: z.number().int().optional(),
  visible: z.boolean().optional(),
  scheduledAt: z.number().int().nullable().optional(),
  expiresAt: z.number().int().nullable().optional(),
  data: z.record(z.string(), z.unknown()).optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
  updatedBy: z.string().nullable().optional(),
})

export type CreateDocumentInput = z.infer<typeof createDocumentSchema>
export type UpdateDocumentInput = z.infer<typeof updateDocumentSchema>
