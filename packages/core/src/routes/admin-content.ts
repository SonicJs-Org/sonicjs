import type { D1Database } from '@cloudflare/workers-types'
import { Hono } from 'hono'
import { html } from 'hono/html'
import type { Bindings, Variables } from '../app'
import { requireAuth, requireRole } from '../middleware'
import { isPluginActive } from '../middleware/plugin-middleware'
import { CACHE_CONFIGS, getCacheService } from '../services/cache'
import { PluginService } from '../services/plugin-service'
import { ContentFormData, renderContentFormPage } from '../templates/pages/admin-content-form.template'
import { ContentListPageData, renderContentListPage } from '../templates/pages/admin-content-list.template'
import { getBlocksFieldConfig, parseBlocksValue } from '../utils/blocks'
import { escapeHtml, sanitizeRichText } from '../utils/sanitize'
import { buildSchemaFieldOptions, resolveSchemaFieldType } from './admin-content-field-types'
import { DocumentTypeRegistry } from '../services/document-type-registry'
import { DocumentsService } from '../services/documents'
import { renderDocumentFormPage } from '../templates/pages/admin-documents-form.template'
import { createDocumentSchema } from '../schemas/document'
import type { QueryableField } from '../schemas/document'
import { loadCollectionConfigs, getVisibleCollections } from '../services/collection-loader'

const adminContentRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Field definition type for form processing
interface FieldDefinition {
  field_name: string
  field_label: string
  field_type: string
  field_options?: any
  is_required?: boolean
}

// Result of parsing a single field value
interface ParsedFieldResult {
  value: any
  errors: string[]
}

/**
 * Parse a single field value from form data with validation
 * Centralizes field parsing logic used in POST, PUT, and preview handlers
 */
function parseFieldValue(
  field: FieldDefinition,
  formData: FormData,
  options: { skipValidation?: boolean } = {}
): ParsedFieldResult {
  const { skipValidation = false } = options
  const value = formData.get(field.field_name)
  const errors: string[] = []

  // Handle blocks fields (array with blocks config)
  const blocksConfig = getBlocksFieldConfig(field.field_options)
  if (blocksConfig) {
    const parsed = parseBlocksValue(value, blocksConfig)
    if (!skipValidation && field.is_required && parsed.value.length === 0) {
      parsed.errors.push(`${field.field_label} is required`)
    }
    return { value: parsed.value, errors: parsed.errors }
  }

  // Required field validation
  if (!skipValidation && field.is_required && (!value || value.toString().trim() === '')) {
    return { value: null, errors: [`${field.field_label} is required`] }
  }

  // Type-specific parsing
  switch (field.field_type) {
    case 'number':
      if (value && isNaN(Number(value))) {
        if (!skipValidation) {
          errors.push(`${field.field_label} must be a valid number`)
        }
        return { value: null, errors }
      }
      return { value: value ? Number(value) : null, errors: [] }

    case 'boolean':
      // Check for the hidden _submitted field to determine if checkbox was rendered
      const submitted = formData.get(`${field.field_name}_submitted`)
      return { value: submitted ? value === 'true' : false, errors: [] }

    case 'select':
      if (field.field_options?.multiple) {
        return { value: formData.getAll(`${field.field_name}[]`), errors: [] }
      }
      return { value: value, errors: [] }

    case 'array': {
      if (!value || value.toString().trim() === '') {
        if (!skipValidation && field.is_required) {
          errors.push(`${field.field_label} is required`)
        }
        return { value: [], errors }
      }
      try {
        const parsed = JSON.parse(value.toString())
        if (!Array.isArray(parsed)) {
          if (!skipValidation) {
            errors.push(`${field.field_label} must be a JSON array`)
          }
          return { value: [], errors }
        }
        if (!skipValidation && field.is_required && parsed.length === 0) {
          errors.push(`${field.field_label} is required`)
        }
        return { value: parsed, errors }
      } catch {
        if (!skipValidation) {
          errors.push(`${field.field_label} must be valid JSON`)
        }
        return { value: [], errors }
      }
    }

    case 'object': {
      if (!value || value.toString().trim() === '') {
        if (!skipValidation && field.is_required) {
          errors.push(`${field.field_label} is required`)
        }
        return { value: {}, errors }
      }
      try {
        const parsed = JSON.parse(value.toString())
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          if (!skipValidation) {
            errors.push(`${field.field_label} must be a JSON object`)
          }
          return { value: {}, errors }
        }
        if (!skipValidation && field.is_required && Object.keys(parsed).length === 0) {
          errors.push(`${field.field_label} is required`)
        }
        return { value: parsed, errors }
      } catch {
        if (!skipValidation) {
          errors.push(`${field.field_label} must be valid JSON`)
        }
        return { value: {}, errors }
      }
    }

    case 'json': {
      if (!value || value.toString().trim() === '') {
        if (!skipValidation && field.is_required) {
          errors.push(`${field.field_label} is required`)
        }
        return { value: null, errors }
      }
      try {
        return { value: JSON.parse(value.toString()), errors: [] }
      } catch {
        if (!skipValidation) {
          errors.push(`${field.field_label} must be valid JSON`)
        }
        return { value: null, errors }
      }
    }

    default:
      return { value: value, errors: [] }
  }
}

/**
 * Extract all field values from form data
 */
function extractFieldData(
  fields: FieldDefinition[],
  formData: FormData,
  options: { skipValidation?: boolean } = {}
): { data: Record<string, any>; errors: Record<string, string[]> } {
  const data: Record<string, any> = {}
  const errors: Record<string, string[]> = {}

  for (const field of fields) {
    const result = parseFieldValue(field, formData, options)
    data[field.field_name] = result.value
    if (result.errors.length > 0) {
      errors[field.field_name] = result.errors
    }
  }

  return { data, errors }
}

// Apply authentication middleware
adminContentRoutes.use('*', requireAuth())

// Get collection fields
async function getCollectionFields(db: D1Database, collectionId: string) {
  console.log(`[getCollectionFields] Loading fields for collection: ${collectionId}`)

  // First, check if document type has a schema in database
  const collectionStmt = db.prepare('SELECT schema, queryable_fields FROM document_types WHERE id = ?')
  const collectionRow = await collectionStmt.bind(collectionId).first() as any

  if (collectionRow) {
    console.log(`[getCollectionFields] Found in database`)
    try {
      const schema = collectionRow.schema
        ? (typeof collectionRow.schema === 'string' ? JSON.parse(collectionRow.schema) : collectionRow.schema)
        : {}
      if (schema && schema.properties) {
        const fieldCount = Object.keys(schema.properties).length
        console.log(`[getCollectionFields] Database schema has ${fieldCount} fields`)
        // Convert schema properties to field format
        let fieldOrder = 0
        return Object.entries(schema.properties).map(([fieldName, fieldConfig]: [string, any]) => {
          const fieldOptions = buildSchemaFieldOptions(fieldConfig)

          return {
            id: `schema-${fieldName}`,
            field_name: fieldName,
            field_type: resolveSchemaFieldType(fieldConfig),
            field_label: fieldConfig.title || fieldName,
            field_options: fieldOptions,
            field_order: fieldOrder++,
            is_required: fieldConfig.required === true || (schema.required && schema.required.includes(fieldName)),
            is_searchable: false
          }
        })
      }

      // Schema has no properties (e.g. anyObject passthrough registered via bootstrapDocumentTypes).
      // Check if there's a matching code collection with a full schema first.
      const codeCollections = await loadCollectionConfigs()
      const codeMatch = codeCollections.find((c: any) => c.name === collectionId)
      if (codeMatch && codeMatch.schema?.properties) {
        console.log(`[getCollectionFields] DB doc type has no properties — using code collection schema`)
        // Fall through to the code collection path below by returning early from the try block
        // (we'll pick it up in the code-collections block after this if/try)
      } else {
        // No code collection either — generate default fields: title + slug always; plus queryable scalars.
        console.log(`[getCollectionFields] Generating default fields from queryable_fields`)
        const queryableFields: Array<{ name: string; kind: string; type: string }> =
          collectionRow.queryable_fields
            ? JSON.parse(typeof collectionRow.queryable_fields === 'string' ? collectionRow.queryable_fields : JSON.stringify(collectionRow.queryable_fields))
            : (schema.queryableFields ?? [])

        const defaultFields: any[] = [
          { id: 'schema-title', field_name: 'title', field_type: 'text', field_label: 'Title', field_options: null, field_order: 0, is_required: true, is_searchable: true },
          { id: 'schema-slug', field_name: 'slug', field_type: 'slug', field_label: 'Slug', field_options: null, field_order: 1, is_required: true, is_searchable: false },
        ]
        let order = 2
        for (const qf of queryableFields) {
          if (qf.name === 'title' || qf.name === 'slug') continue
          defaultFields.push({
            id: `schema-${qf.name}`,
            field_name: qf.name,
            field_type: qf.type === 'integer' ? 'number' : 'text',
            field_label: qf.name.charAt(0).toUpperCase() + qf.name.slice(1).replace(/([A-Z])/g, ' $1'),
            field_options: null,
            field_order: order++,
            is_required: false,
            is_searchable: false,
          })
        }
        return defaultFields
      }
    } catch (e) {
      console.error('[getCollectionFields] Error parsing database collection schema:', e)
    }
  }

  console.log(`[getCollectionFields] Not in database, checking code collections`)

  // Check code-defined collections (don't cache these since they can change)
  const codeCollections = await loadCollectionConfigs()
  console.log(`[getCollectionFields] Found ${codeCollections.length} code collections`)

  const codeCollection = codeCollections.find((c: any) => c.name === collectionId)

  if (codeCollection && codeCollection.schema) {
    console.log(`[getCollectionFields] Found code collection: ${collectionId}`)
    try {
      const schema = codeCollection.schema
      if (schema && schema.properties) {
        const fieldCount = Object.keys(schema.properties).length
        console.log(`[getCollectionFields] Code collection schema has ${fieldCount} fields`)
        // Convert schema properties to field format
        let fieldOrder = 0
        return Object.entries(schema.properties).map(([fieldName, fieldConfig]: [string, any]) => {
          const fieldOptions = buildSchemaFieldOptions(fieldConfig)

          return {
            id: `schema-${fieldName}`,
            field_name: fieldName,
            field_type: resolveSchemaFieldType(fieldConfig),
            field_label: fieldConfig.title || fieldName,
            field_options: fieldOptions,
            field_order: fieldOrder++,
            is_required: fieldConfig.required === true || (schema.required && schema.required.includes(fieldName)),
            is_searchable: false
          }
        })
      }
    } catch (e) {
      console.error('[getCollectionFields] Error parsing code collection schema:', e)
    }
  } else {
    console.log(`[getCollectionFields] Code collection "${collectionId}" not found`)
  }

  console.log(`[getCollectionFields] Returning 0 fields`)
  return []
}

// Get collection by ID
async function getCollection(db: D1Database, collectionId: string) {
  console.log(`[getCollection] Loading collection by ID: ${collectionId}`)
  const cache = getCacheService(CACHE_CONFIGS.collection!)

  return cache.getOrSet(
    cache.generateKey('collection', collectionId),
    async () => {
      console.log(`[getCollection] Cache miss, querying database`)
      const stmt = db.prepare('SELECT * FROM document_types WHERE id = ? AND is_active = 1')
      const collection = await stmt.bind(collectionId).first() as any

      if (collection) {
        console.log(`[getCollection] Found in database`)
        return {
          id: collection.id,
          name: collection.name,
          display_name: collection.display_name,
          description: collection.description,
          schema: collection.schema ? JSON.parse(collection.schema) : {}
        }
      }

      console.log(`[getCollection] Not in database, checking code collections`)
      // Check code-defined collections
      const codeCollections = await loadCollectionConfigs()
      const codeCollection = codeCollections.find((c: any) => c.name === collectionId)

      if (codeCollection) {
        console.log(`[getCollection] Found code collection: ${collectionId}`)
        return {
          id: codeCollection.name,
          name: codeCollection.name,
          display_name: codeCollection.displayName,
          description: codeCollection.description,
          schema: codeCollection.schema || {}
        }
      }

      console.log(`[getCollection] Not found: ${collectionId}`)
      return null
    }
  )
}

// ─── Document-backing (Option B) ────────────────────────────────────────────────
// A collection is "document-backed" when a document type with the SAME id as the collection name is
// registered + active (e.g. the `blog_post` collection ↔ the `blog_post` document type). Such
// collections keep the rich /admin/content editor UI but store data in the `documents` table.
async function getDocBackingType(db: D1Database, collectionName?: string | null) {
  if (!collectionName) return null
  const dt = await new DocumentTypeRegistry(db).findById(collectionName)
  return dt && dt.isActive ? dt : null
}

async function getCollectionByName(db: D1Database, name: string) {
  console.log(`[getCollectionByName] Loading collection by name: ${name}`)
  const row = await db.prepare('SELECT * FROM document_types WHERE name = ? AND is_active = 1').bind(name).first() as any
  if (row) {
    console.log(`[getCollectionByName] Found in database`)
    return {
      id: row.id, name: row.name, display_name: row.display_name,
      description: row.description, schema: row.schema ? JSON.parse(row.schema) : {},
    }
  }

  console.log(`[getCollectionByName] Not in database, checking code collections`)
  // Check code-defined collections
  const codeCollections = await loadCollectionConfigs()
  const codeCollection = codeCollections.find((c: any) => c.name === name)

  if (codeCollection) {
    console.log(`[getCollectionByName] Found code collection: ${name}`)
    return {
      id: codeCollection.name,
      name: codeCollection.name,
      display_name: codeCollection.displayName,
      description: codeCollection.description,
      schema: codeCollection.schema || {}
    }
  }

  console.log(`[getCollectionByName] Not found: ${name}`)
  return null
}

// Rich-editor plugin flags/settings the content form needs (Quill/TinyMCE/MDX/workflow), so a
// document-backed edit form looks identical to the legacy content editor.
async function loadContentEditorFlags(db: D1Database): Promise<Record<string, unknown>> {
  const flags: Record<string, unknown> = { workflowEnabled: await isPluginActive(db, 'workflow') }
  const editors: Array<[string, string]> = [
    ['tinymce-plugin', 'tinymce'],
    ['quill-editor', 'quill'],
    ['easy-mdx', 'mdxeditor'],
    ['lexical-editor', 'lexical'],
  ]
  for (const [plugin, key] of editors) {
    const enabled = await isPluginActive(db, plugin)
    flags[`${key}Enabled`] = enabled
    if (enabled) {
      const ps = new PluginService(db)
      const p = await ps.getPlugin(plugin)
      flags[`${key}Settings`] = p?.settings
    }
  }
  return flags
}

function makeDocService(db: D1Database, docType: any, tenantId: string) {
  return new DocumentsService(db, {
    queryableFields: docType.queryableFields ?? [],
    typeSchemaVersion: docType.schemaVersion ?? 1,
    maxVersionsPerRoot: docType.settings?.maxVersionsPerRoot ?? 50,
    tenantId,
    versioning: docType.settings?.versioning ?? false,
  })
}

/** Tenant for this request (resolved by tenantMiddleware; 'default' when single-tenant). */
function reqTenant(c: any): string {
  return (c.get('tenantId') as string | undefined) ?? 'default'
}

function slugify(s?: string | null): string | null {
  if (!s) return null
  return s.toLowerCase().replace(/[^a-z0-9\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-').replace(/^-+|-+$/g, '') || null
}

// Content list (main page)
adminContentRoutes.get('/', async (c) => {
  try {
    const user = c.get('user')
    const url = new URL(c.req.url)
    const db = c.env.DB

    // Get query parameters
    const page = parseInt(url.searchParams.get('page') || '1')
    const limit = parseInt(url.searchParams.get('limit') || '20')
    const modelName = url.searchParams.get('model') || 'all'
    const status = url.searchParams.get('status') || 'all'
    const search = url.searchParams.get('search') || ''
    const offset = (page - 1) * limit

    // Get all document types for filter dropdown (database)
    const collectionsStmt = db.prepare("SELECT id, name, display_name FROM document_types WHERE is_active = 1 ORDER BY display_name")
    const { results: collectionsResults } = await collectionsStmt.all()

    // Load code-defined collections
    const codeCollections = await loadCollectionConfigs()
    const codeCollectionMap = new Map(codeCollections.map((c: any) => [c.name, c]))

    // Also include active document types in the models dropdown (prefixed with doc: to distinguish).
    // Internal/auth-owned types (user_profile, plugin, rbac_*, site_settings, tenant, …) must NOT appear
    // as selectable content models — filter them out of every dropdown source, not just `docTypes`.
    const docTypeRegistry = new DocumentTypeRegistry(db)
    const docTypes = (await docTypeRegistry.findAll()).filter(dt => !dt.settings?.internal && !dt.isAuth)
    const visibleTypeIds = new Set(docTypes.map(dt => dt.id))

    // Merge database and code collections (db takes precedence). The raw document_types query above is
    // unfiltered, so drop internal/auth types here using the registry-derived visible set.
    const allCollections = [
      ...codeCollections.filter((c: any) => !collectionsResults?.find((r: any) => r.name === c.name)),
      ...(collectionsResults || []).filter((row: any) => visibleTypeIds.has(row.id)).map((row: any) => ({ name: row.name, displayName: row.display_name }))
    ]

    // A document type whose id matches a collection name backs that collection (Option B) and is
    // managed through the collection entry — don't also list it as a separate doc: model.
    const collectionNames = new Set(allCollections.map((c: any) => c.name))
    const models = [
      ...allCollections.map((c: any) => ({ name: c.name, displayName: c.displayName })),
      ...docTypes.filter(dt => !collectionNames.has(dt.id)).map(dt => ({ name: `doc:${dt.id}`, displayName: dt.displayName })),
    ]

    // Non-internal collections for the "New Content" dropdown — same filtering as /admin/collections.
    const newContentCollections = await getVisibleCollections(db)

    // ── Document-type branch: query documents table instead of content ──────────
    // Triggered by a `doc:` model OR a document-backed collection (collection name == doc type id).
    const docBackedCollection = !modelName.startsWith('doc:') && modelName !== 'all'
      ? docTypes.find(dt => dt.id === modelName)
      : undefined
    const isDocModel = modelName.startsWith('doc:') || !!docBackedCollection
    if (isDocModel) {
      const typeId = modelName.startsWith('doc:') ? modelName.slice(4) : modelName
      const docType = docTypes.find(dt => dt.id === typeId)

      const docParams: (string | number)[] = [reqTenant(c), typeId]
      let docSql = `SELECT * FROM documents WHERE tenant_id = ? AND type_id = ? AND is_current_draft = 1`
      // D32: honor the ?status= filter (mirror the all-view union's doc-half mapping). 'deleted' shows
      // soft-deleted roots; published/draft refine by the published flag; 'all' shows the working set.
      if (status === 'deleted') docSql += ' AND deleted_at IS NOT NULL'
      else {
        docSql += ' AND deleted_at IS NULL'
        if (status === 'published') docSql += ' AND is_published = 1'
        else if (status === 'draft') docSql += ' AND is_published = 0'
      }
      if (search) {
        docSql += ` AND (title LIKE ? OR json_extract(data,'$.question') LIKE ? OR json_extract(data,'$.authorName') LIKE ? OR json_extract(data,'$.name') LIKE ?)`
        const term = `%${search}%`
        docParams.push(term, term, term, term)
      }
      const countRow = await db.prepare(docSql.replace('SELECT *', 'SELECT COUNT(*) as count')).bind(...docParams).first() as any
      docSql += ' ORDER BY updated_at DESC LIMIT ? OFFSET ?'
      docParams.push(limit, offset)
      const { results: docRows } = await db.prepare(docSql).bind(...docParams).all()

      const statusBadgeCss = {
        published: 'bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20',
        draft: 'bg-zinc-50 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-400 ring-1 ring-inset ring-zinc-600/20 dark:ring-zinc-500/20',
      }
      const contentItems = (docRows || []).map((row: any) => {
        const data = JSON.parse(row.data ?? '{}')
        const label = row.is_published ? 'Published' : 'Draft'
        const css = row.is_published ? statusBadgeCss.published : statusBadgeCss.draft
        return {
          // Doc-backed collections edit through the rich collection editor at /admin/content/:rootId/edit;
          // pure doc: types use the generic document form at /admin/content/documents/:typeId/:rootId.
          id: docBackedCollection ? row.root_id : `documents/${typeId}/${row.root_id}`,
          title: row.title || data.question || data.authorName || data.name || row.root_id,
          slug: row.slug || '',
          modelName: docType?.displayName ?? typeId,
          statusBadge: `<span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ${css}">${label}</span>`,
          authorName: row.created_by || 'System',
          // Document timestamps are stored in SECONDS (documents.ts), unlike legacy content rows which
          // store MILLISECONDS — hence the *1000 here (D23).
          formattedDate: new Date((row.updated_at ?? 0) * 1000).toLocaleDateString(),
          // No list-level publish/unpublish for document rows (D14): those content-list action endpoints
          // operate on the legacy `content` table and are keyed by a version :documentId, not root_id.
          // Publish/unpublish happen in the edit form, which posts to the working document routes.
          availableActions: [],
        }
      })

      return c.html(renderContentListPage({
        modelName, status, page, search, models, newContentCollections, contentItems,
        totalItems: countRow?.count ?? 0,
        itemsPerPage: limit,
        user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
        version: c.get('appVersion'),
      }))
    }

    // ── All-view documents list ────────────────────────────────────────────────
    // The document-model POC keeps legacy `content` paths available, but the All view is
    // a documents-only list over every active document type.
    if (modelName === 'all') {
      const allTypeIds = docTypes.map(dt => dt.id)
      const like = search ? `%${search}%` : null
      const docConds = ['d.is_current_draft = 1', 'd.tenant_id = ?']
      const docParams: any[] = [reqTenant(c)]
      if (allTypeIds.length > 0) {
        const ph = allTypeIds.map(() => '?').join(',')
        docConds.push(`d.type_id IN (${ph})`)
        docParams.push(...allTypeIds)
      }
      if (status === 'deleted') docConds.push('d.deleted_at IS NOT NULL')
      else {
        docConds.push('d.deleted_at IS NULL')
        if (status === 'published') docConds.push('d.is_published = 1')
        else if (status === 'draft') docConds.push('d.is_published = 0')
      }
      if (like) { docConds.push("(d.title LIKE ? OR json_extract(d.data,'$.author') LIKE ?)"); docParams.push(like, like) }

      const unionSql = `
        SELECT d.root_id AS id, d.title AS title, d.slug AS slug,
               CASE WHEN d.is_published = 1 THEN 'published' ELSE 'draft' END AS status,
               d.updated_at * 1000 AS updated_at,
               dt.display_name AS cdisplay, COALESCE(d.created_by, 'System') AS author_label
        FROM documents d JOIN document_types dt ON dt.id = d.type_id
        WHERE ${docConds.join(' AND ')}
        ORDER BY updated_at DESC LIMIT ? OFFSET ?`
      const { results: unionRows } = await db.prepare(unionSql).bind(...docParams, limit, offset).all()

      const countRow = await db.prepare(
        `SELECT COUNT(*) AS count FROM documents d WHERE ${docConds.join(' AND ')}`,
      ).bind(...docParams).first() as any

      const badge: Record<string, string> = {
        published: 'bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20',
        draft: 'bg-zinc-50 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-400 ring-1 ring-inset ring-zinc-600/20 dark:ring-zinc-500/20',
        deleted: 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-600/20 dark:ring-red-500/20',
      }
      const contentItems = (unionRows || []).map((row: any) => ({
        id: row.id,
        title: row.title || row.slug || row.id,
        slug: row.slug || '',
        modelName: row.cdisplay,
        statusBadge: `<span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ${badge[row.status] ?? badge.draft}">${row.status}</span>`,
        authorName: row.author_label,
        formattedDate: new Date(row.updated_at ?? 0).toLocaleDateString(),
        availableActions: [],
      }))

      return c.html(renderContentListPage({
        modelName, status, page, search, models, newContentCollections, contentItems,
        totalItems: countRow?.count ?? 0,
        itemsPerPage: limit,
        user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
        version: c.get('appVersion'),
      }))
    }

    const emptyPageData: ContentListPageData = {
      modelName,
      status,
      page,
      search,
      models,
      newContentCollections,
      contentItems: [],
      totalItems: 0,
      itemsPerPage: limit,
      user: user ? {
        name: user!.email,
        email: user!.email,
        role: user!.role
      } : undefined,
      version: c.get('appVersion')
    }
    return c.html(renderContentListPage(emptyPageData))

    // ── Legacy content branch ──────────────────────────────────────────────────
    // Build where conditions
    const conditions: string[] = []
    const params: any[] = []

    // Hide content from form-sourced collections in the regular content list
    conditions.push("(col.source_type IS NULL OR col.source_type = 'user')")

    // Always filter out deleted content unless specifically requested
    if (status !== 'deleted') {
      conditions.push("c.status != 'deleted'")
    }

    if (search) {
      conditions.push('(c.title LIKE ? OR c.slug LIKE ? OR c.data LIKE ?)')
      params.push(`%${search}%`, `%${search}%`, `%${search}%`)
    }

    if (modelName !== 'all') {
      conditions.push('col.name = ?')
      params.push(modelName)
    }

    if (status !== 'all' && status !== 'deleted') {
      conditions.push('c.status = ?')
      params.push(status)
    } else if (status === 'deleted') {
      conditions.push("c.status = 'deleted'")
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''

    // Get total count
    const countStmt = db.prepare(`
      SELECT COUNT(*) as count
      FROM content c
      JOIN collections col ON c.collection_id = col.id
      ${whereClause}
    `)
    const countResult = await countStmt.bind(...params).first() as any
    const totalItems = countResult?.count || 0

    // Get content items
    const contentStmt = db.prepare(`
      SELECT c.id, c.title, c.slug, c.status, c.created_at, c.updated_at,
             col.name as collection_name, col.display_name as collection_display_name,
             u.first_name, u.last_name, u.email as author_email
      FROM content c
      JOIN collections col ON c.collection_id = col.id
      LEFT JOIN auth_user u ON c.author_id = u.id
      ${whereClause}
      ORDER BY c.updated_at DESC
      LIMIT ? OFFSET ?
    `)
    const { results } = await contentStmt.bind(...params, limit, offset).all()

    // Process content items
    const contentItems = (results || []).map((row: any) => {
      const statusConfig: Record<string, { class: string; text: string }> = {
        draft: {
          class: 'bg-zinc-50 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-400 ring-1 ring-inset ring-zinc-600/20 dark:ring-zinc-500/20',
          text: 'Draft'
        },
        review: {
          class: 'bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 ring-1 ring-inset ring-amber-600/20 dark:ring-amber-500/20',
          text: 'Under Review'
        },
        scheduled: {
          class: 'bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-400 ring-1 ring-inset ring-blue-600/20 dark:ring-blue-500/20',
          text: 'Scheduled'
        },
        published: {
          class: 'bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20',
          text: 'Published'
        },
        archived: {
          class: 'bg-purple-50 dark:bg-purple-500/10 text-purple-700 dark:text-purple-400 ring-1 ring-inset ring-purple-600/20 dark:ring-purple-500/20',
          text: 'Archived'
        },
        deleted: {
          class: 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-600/20 dark:ring-red-500/20',
          text: 'Deleted'
        }
      }

      const config = statusConfig[row.status as keyof typeof statusConfig] || statusConfig.draft
      const statusBadge = `
        <span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ${config?.class || ''}">
          ${config?.text || row.status}
        </span>
      `

      const authorName = row.first_name && row.last_name
        ? `${row.first_name} ${row.last_name}`
        : row.author_email || 'Unknown'

      const formattedDate = new Date(row.updated_at).toLocaleDateString()

      // Determine available workflow actions based on status
      const availableActions: string[] = []
      switch (row.status) {
        case 'draft':
          availableActions.push('submit_for_review', 'publish')
          break
        case 'review':
          availableActions.push('approve', 'request_changes')
          break
        case 'published':
          availableActions.push('unpublish', 'archive')
          break
        case 'scheduled':
          availableActions.push('unschedule')
          break
      }

      return {
        id: row.id,
        title: row.title,
        slug: row.slug,
        modelName: row.collection_display_name,
        statusBadge,
        authorName,
        formattedDate,
        availableActions
      }
    })

    const pageData: ContentListPageData = {
      modelName,
      status,
      page,
      search,
      models,
      newContentCollections,
      contentItems,
      totalItems,
      itemsPerPage: limit,
      user: user ? {
        name: user?.email ?? '',
        email: user?.email ?? '',
        role: user?.role ?? ''
      } : undefined,
      version: c.get('appVersion')
    }

    return c.html(renderContentListPage(pageData))
  } catch (error) {
    console.error('Error fetching content list:', error)
    return c.html(`<p>Error loading content: ${error}</p>`)
  }
})

// New content form
adminContentRoutes.get('/new', async (c) => {
  try {
    const user = c.get('user')
    const url = new URL(c.req.url)
    const collectionId = url.searchParams.get('collection')

    if (!collectionId) {
      // Show collection selection page
      const db = c.env.DB
      // Get all document types for content creation (database)
      const collectionsStmt = db.prepare("SELECT id, name, display_name, description FROM document_types WHERE is_active = 1 ORDER BY display_name")
      const { results } = await collectionsStmt.all()

      // Internal/auth-owned types (media_asset, plugin, rbac_*, site_settings, tenant, …) are not
      // content — they must not be offered as a "create new content" collection.
      const visibleTypeIds = new Set(
        (await new DocumentTypeRegistry(db).findAll())
          .filter(dt => !dt.settings?.internal && !dt.isAuth)
          .map(dt => dt.id),
      )

      // Load code-defined collections
      const codeCollections = await loadCollectionConfigs()

      // Merge code and database collections
      const dbCollectionNames = new Set((results || []).map((r: any) => r.name))
      const allCollections = [
        ...codeCollections.filter((c: any) => !dbCollectionNames.has(c.name)).map((c: any) => ({
          id: c.name,
          name: c.name,
          display_name: c.displayName,
          description: c.description
        })),
        ...(results || []).filter((row: any) => visibleTypeIds.has(row.id)).map((row: any) => ({
          id: row.id,
          name: row.name,
          display_name: row.display_name,
          description: row.description
        }))
      ]

      const collections = allCollections

      // Render collection selection page
      const selectionHTML = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Select Collection - SonicJS AI Admin</title>
          <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-900 text-white">
          <div class="min-h-screen flex items-center justify-center">
            <div class="max-w-2xl w-full mx-auto p-8">
              <h1 class="text-3xl font-bold mb-8 text-center">Create New Content</h1>
              <p class="text-gray-300 text-center mb-8">Select a collection to create content in:</p>
              
              <div class="grid gap-4">
                ${collections.map(collection => `
                  <a href="/admin/content/new?collection=${collection.id}" 
                     class="block p-6 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors border border-gray-700">
                    <h3 class="text-xl font-semibold mb-2">${collection.display_name}</h3>
                    <p class="text-gray-400">${collection.description || 'No description'}</p>
                  </a>
                `).join('')}
              </div>
              
              <div class="mt-8 text-center">
                <a href="/admin/content" class="text-blue-400 hover:text-blue-300">← Back to Content List</a>
              </div>
            </div>
          </div>
        </body>
        </html>
      `

      return c.html(selectionHTML)
    }

    const db = c.env.DB
    // Resolve ?collection= by id OR name. The content-list "New" button passes the collection id, but
    // a collection name (== document type id for doc-backed collections, e.g. ?collection=blog_post)
    // is the stable identifier callers/links use — accept both so the form always carries a collection_id.
    const collection = (await getCollection(db, collectionId)) ?? (await getCollectionByName(db, collectionId))

    if (!collection) {
      const formData: ContentFormData = {
        collection: { id: '', name: '', display_name: 'Unknown', schema: {} },
        fields: [],
        error: 'Collection not found.',
        user: user ? {
          name: user.email,
          email: user.email,
          role: user.role
        } : undefined
      }
      return c.html(renderContentFormPage(formData))
    }

    // Use the RESOLVED collection id (the ?collection= param may have been a name).
    const fields = await getCollectionFields(db, collection.id)

    // Check if workflow plugin is active
    const workflowEnabled = await isPluginActive(db, 'workflow')

    // Check if TinyMCE plugin is active and get settings
    const tinymceEnabled = await isPluginActive(db, 'tinymce-plugin')
    let tinymceSettings
    if (tinymceEnabled) {
      const pluginService = new PluginService(db)
      const tinymcePlugin = await pluginService.getPlugin('tinymce-plugin')
      tinymceSettings = tinymcePlugin?.settings
    }

    // Check if Quill plugin is active and get settings
    const quillEnabled = await isPluginActive(db, 'quill-editor')
    let quillSettings
    if (quillEnabled) {
      const pluginService = new PluginService(db)
      const quillPlugin = await pluginService.getPlugin('quill-editor')
      quillSettings = quillPlugin?.settings
    }

    // Check if MDXEditor plugin is active and get settings
    const mdxeditorEnabled = await isPluginActive(db, 'easy-mdx')
    let mdxeditorSettings
    if (mdxeditorEnabled) {
      const pluginService = new PluginService(db)
      const mdxeditorPlugin = await pluginService.getPlugin('easy-mdx')
      mdxeditorSettings = mdxeditorPlugin?.settings
    }

    // Check if Lexical Editor plugin is active and get settings
    const lexicalEnabled = await isPluginActive(db, 'lexical-editor')
    let lexicalSettings
    if (lexicalEnabled) {
      const pluginService = new PluginService(db)
      const lexicalPlugin = await pluginService.getPlugin('lexical-editor')
      lexicalSettings = lexicalPlugin?.settings
    }

    console.log('[Content Form /new] Editor plugins status:', {
      tinymce: tinymceEnabled,
      quill: quillEnabled,
      mdxeditor: mdxeditorEnabled,
      lexical: lexicalEnabled,
    })

    const formData: ContentFormData = {
      collection,
      fields,
      isEdit: false,
      workflowEnabled,
      tinymceEnabled,
      tinymceSettings,
      quillEnabled,
      quillSettings,
      mdxeditorEnabled,
      mdxeditorSettings,
      lexicalEnabled,
      lexicalSettings,
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined
    }

    return c.html(renderContentFormPage(formData))
  } catch (error) {
    console.error('Error loading new content form:', error)
    const formData: ContentFormData = {
      collection: { id: '', name: '', display_name: 'Unknown', schema: {} },
      fields: [],
      error: 'Failed to load content form.',
      user: c.get('user') ? {
        name: c.get('user')!.email,
        email: c.get('user')!.email,
        role: c.get('user')!.role
      } : undefined
    }
    return c.html(renderContentFormPage(formData))
  }
})

// Edit content form
adminContentRoutes.get('/:id/edit', async (c) => {
  try {
    const id = c.req.param('id')
    const user = c.get('user')
    const db = c.env.DB
    const url = new URL(c.req.url)

    // Capture referrer parameters to preserve filters when returning to list
    const referrerParams = url.searchParams.get('ref') || ''

    // ── Option B: if :id is a document-backed root, render the rich editor from the document ──
    const docRow = await db
      .prepare("SELECT * FROM documents WHERE root_id = ? AND is_current_draft = 1 AND tenant_id = ? AND deleted_at IS NULL")
      .bind(id, reqTenant(c)).first() as any
    if (docRow) {
      const docType = await getDocBackingType(db, docRow.type_id)
      const dcoll = docType ? await getCollectionByName(db, docRow.type_id) : null
      if (docType && dcoll) {
        const fields = await getCollectionFields(db, dcoll.id)
        const flags = await loadContentEditorFlags(db)
        const formData: ContentFormData = {
          id: docRow.root_id,
          title: docRow.title,
          slug: docRow.slug,
          created_at: docRow.created_at,
          updated_at: docRow.updated_at,
          published_at: docRow.published_at,
          data: docRow.data ? JSON.parse(docRow.data) : {},
          status: docRow.is_published ? 'published' : (docRow.status ?? 'draft'),
          collection: dcoll,
          fields,
          isEdit: true,
          referrerParams,
          versioningEnabled: docType?.settings?.versioning === true,
          user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
          version: c.get('appVersion'),
          ...flags,
        } as ContentFormData
        return c.html(renderContentFormPage(formData))
      }
    }

    const notFoundData: ContentFormData = {
      collection: { id: '', name: '', display_name: 'Unknown', schema: {} },
      fields: [],
      error: 'Content not found.',
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined
    }
    return c.html(renderContentFormPage(notFoundData))

    // Get content with caching
    const cache = getCacheService(CACHE_CONFIGS.content!)
    const content = await cache.getOrSet(
      cache.generateKey('content', id),
      async () => {
        const contentStmt = db.prepare(`
          SELECT c.*, col.id as collection_id, col.name as collection_name,
                 col.display_name as collection_display_name, col.description as collection_description,
                 col.schema as collection_schema
          FROM content c
          JOIN collections col ON c.collection_id = col.id
          WHERE c.id = ?
        `)
        return await contentStmt.bind(id).first() as any
      }
    )

    if (!content) {
      const formData: ContentFormData = {
        collection: { id: '', name: '', display_name: 'Unknown', schema: {} },
        fields: [],
        error: 'Content not found.',
        user: user ? {
          name: user!.email,
          email: user!.email,
          role: user!.role
        } : undefined
      }
      return c.html(renderContentFormPage(formData))
    }

    const collection = {
      id: content.collection_id,
      name: content.collection_name,
      display_name: content.collection_display_name,
      description: content.collection_description,
      schema: content.collection_schema ? JSON.parse(content.collection_schema) : {}
    }

    const fields = await getCollectionFields(db, content.collection_id)
    const contentData = content.data ? JSON.parse(content.data) : {}

    // Check if workflow plugin is active
    const workflowEnabled = await isPluginActive(db, 'workflow')

    // Check if TinyMCE plugin is active and get settings
    const tinymceEnabled = await isPluginActive(db, 'tinymce-plugin')
    let tinymceSettings
    if (tinymceEnabled) {
      const pluginService = new PluginService(db)
      const tinymcePlugin = await pluginService.getPlugin('tinymce-plugin')
      tinymceSettings = tinymcePlugin?.settings
    }

    // Check if Quill plugin is active and get settings
    const quillEnabled = await isPluginActive(db, 'quill-editor')
    let quillSettings
    if (quillEnabled) {
      const pluginService = new PluginService(db)
      const quillPlugin = await pluginService.getPlugin('quill-editor')
      quillSettings = quillPlugin?.settings
    }

    // Check if MDXEditor plugin is active and get settings
    const mdxeditorEnabled = await isPluginActive(db, 'easy-mdx')
    let mdxeditorSettings
    if (mdxeditorEnabled) {
      const pluginService = new PluginService(db)
      const mdxeditorPlugin = await pluginService.getPlugin('easy-mdx')
      mdxeditorSettings = mdxeditorPlugin?.settings
    }

    // Check if Lexical Editor plugin is active and get settings
    const lexicalEnabled = await isPluginActive(db, 'lexical-editor')
    let lexicalSettings
    if (lexicalEnabled) {
      const pluginService = new PluginService(db)
      const lexicalPlugin = await pluginService.getPlugin('lexical-editor')
      lexicalSettings = lexicalPlugin?.settings
    }

    const formData: ContentFormData = {
      id: content.id,
      title: content.title,
      slug: content.slug,
      created_at: content.created_at,
      updated_at: content.updated_at,
      published_at: content.published_at,
      data: contentData,
      status: content.status,
      scheduled_publish_at: content.scheduled_publish_at,
      scheduled_unpublish_at: content.scheduled_unpublish_at,
      review_status: content.review_status,
      meta_title: content.meta_title,
      meta_description: content.meta_description,
      collection,
      fields,
      isEdit: true,
      workflowEnabled,
      tinymceEnabled,
      tinymceSettings,
      quillEnabled,
      quillSettings,
      mdxeditorEnabled,
      mdxeditorSettings,
      lexicalEnabled,
      lexicalSettings,
      referrerParams,
      user: user ? {
        name: user!.email,
        email: user!.email,
        role: user!.role
      } : undefined,
      version: c.get('appVersion')
    }

    return c.html(renderContentFormPage(formData))
  } catch (error) {
    console.error('Error loading edit content form:', error)
    const formData: ContentFormData = {
      collection: { id: '', name: '', display_name: 'Unknown', schema: {} },
      fields: [],
      error: 'Failed to load content for editing.',
      user: c.get('user') ? {
        name: c.get('user')!.email,
        email: c.get('user')!.email,
        role: c.get('user')!.role
      } : undefined
    }
    return c.html(renderContentFormPage(formData))
  }
})

// Create content
adminContentRoutes.post('/', async (c) => {
  try {
    const user = c.get('user')
    const formData = await c.req.formData()
    const collectionId = formData.get('collection_id') as string
    const action = formData.get('action') as string

    if (!collectionId) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Collection ID is required.
        </div>
      `)
    }

    const db = c.env.DB
    const collection = await getCollection(db, collectionId)

    if (!collection) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Collection not found.
        </div>
      `)
    }

    const fields = await getCollectionFields(db, collectionId)

    // Extract and validate field data
    const { data, errors } = extractFieldData(fields, formData)

    // Check for validation errors
    if (Object.keys(errors).length > 0) {
      const formDataWithErrors: ContentFormData = {
        collection,
        fields,
        data,
        validationErrors: errors,
        error: 'Please fix the validation errors below.',
        user: user ? {
          name: user.email,
          email: user.email,
          role: user.role
        } : undefined
      }
      if (c.req.header('HX-Request') === 'true') {
        c.header('HX-Retarget', '#content-form-page')
        c.header('HX-Reswap', 'outerHTML')
        return c.html(renderContentFormPage(formDataWithErrors, { partialOnly: true }))
      }
      return c.html(renderContentFormPage(formDataWithErrors))
    }

    // Generate slug if not provided
    let slug = data.slug || data.title
    if (slug) {
      slug = slug.toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .trim('-')
    }

    // Determine status
    let status = formData.get('status') as string || 'draft'
    if (action === 'save_and_publish') {
      status = 'published'
    }

    // Handle scheduling
    const scheduledPublishAt = formData.get('scheduled_publish_at') as string
    const scheduledUnpublishAt = formData.get('scheduled_unpublish_at') as string

    // ── Option B: document-backed collection → store in `documents`, not `content` ──
    const createDocType = await getDocBackingType(db, collection.name)
    if (createDocType) {
      const tenantId = reqTenant(c)
      const svc = makeDocService(db, createDocType, tenantId)
      const doc = await svc.create(createDocumentSchema.parse({
        typeId: createDocType.id, tenantId, locale: 'default',
        title: data.title || slug || 'Untitled', slug: slug || undefined,
        data, publishOnCreate: status === 'published',
      }), user?.userId)
      const cache = getCacheService(CACHE_CONFIGS.content!)
      await cache.invalidate(`content:list:${collectionId}:*`)
      const redirectUrl = `/admin/content/${doc.rootId}/edit?success=Content created successfully!`
      return c.req.header('HX-Request') === 'true'
        ? c.text('', 200, { 'HX-Redirect': redirectUrl })
        : c.redirect(redirectUrl)
    }

    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Collection is not document-backed.
      </div>
    `, 400)

    // Create content
    const contentId = crypto.randomUUID()
    const now = Date.now()

    const insertStmt = db.prepare(`
      INSERT INTO content (
        id, collection_id, slug, title, data, status,
        author_id, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)

    await insertStmt.bind(
      contentId,
      collectionId,
      slug,
      data.title || 'Untitled',
      JSON.stringify(data),
      status,
      user?.userId || 'unknown',
      now,
      now
    ).run()

    // Invalidate collection content list cache
    const cache = getCacheService(CACHE_CONFIGS.content!)
    await cache.invalidate(`content:list:${collectionId}:*`)

    // Create initial version
    const versionStmt = db.prepare(`
      INSERT INTO content_versions (id, content_id, version, data, author_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `)

    await versionStmt.bind(
      crypto.randomUUID(),
      contentId,
      1,
      JSON.stringify(data),
      user?.userId || 'unknown',
      now
    ).run()

    // Log workflow action
    const workflowStmt = db.prepare(`
      INSERT INTO workflow_history (id, content_id, action, from_status, to_status, user_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)

    await workflowStmt.bind(
      crypto.randomUUID(),
      contentId,
      'created',
      'none',
      status,
      user?.userId || 'unknown',
      now
    ).run()

    // Handle different actions
    const referrerParams = formData.get('referrer_params') as string
    const redirectUrl = action === 'save_and_continue'
      ? `/admin/content/${contentId}/edit?success=Content saved successfully!${referrerParams ? `&ref=${encodeURIComponent(referrerParams)}` : ''}`
      : referrerParams
        ? `/admin/content?${referrerParams}&success=Content created successfully!`
        : `/admin/content?collection=${collectionId}&success=Content created successfully!`

    // Check if this is an HTMX request
    const isHTMX = c.req.header('HX-Request') === 'true'

    if (isHTMX) {
      // For HTMX requests, use HX-Redirect header to trigger client-side redirect
      return c.text('', 200, {
        'HX-Redirect': redirectUrl
      })
    } else {
      // For regular requests, use server-side redirect
      return c.redirect(redirectUrl)
    }

  } catch (error) {
    console.error('Error creating content:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Failed to create content. Please try again.
      </div>
    `)
  }
})

// Update content
adminContentRoutes.put('/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const user = c.get('user')
    const formData = await c.req.formData()
    const action = formData.get('action') as string

    const db = c.env.DB

    // ── Option B: if :id is a document-backed root, save a new draft + sync publish state ──
    const tenantId = reqTenant(c)
    const docRowU = await db
      .prepare("SELECT id, type_id FROM documents WHERE root_id = ? AND is_current_draft = 1 AND tenant_id = ?")
      .bind(id, tenantId).first() as any
    if (docRowU) {
      const docType = await getDocBackingType(db, docRowU.type_id)
      const dcoll = docType ? await getCollectionByName(db, docRowU.type_id) : null
      if (docType && dcoll) {
        const fields = await getCollectionFields(db, dcoll.id)
        const { data, errors } = extractFieldData(fields, formData)
        if (Object.keys(errors).length > 0) {
          const flags = await loadContentEditorFlags(db)
          const errFormData = {
            id, collection: dcoll, fields, data, validationErrors: errors,
            error: 'Please fix the validation errors below.', isEdit: true,
            user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
            ...flags,
          } as ContentFormData
          if (c.req.header('HX-Request') === 'true') {
            c.header('HX-Retarget', '#content-form-page')
            c.header('HX-Reswap', 'outerHTML')
            return c.html(renderContentFormPage(errFormData, { partialOnly: true }))
          }
          return c.html(renderContentFormPage(errFormData))
        }
        const slug = slugify(data.slug || data.title)
        let status = formData.get('status') as string || 'draft'
        if (action === 'save_and_publish') status = 'published'

        const svc = makeDocService(db, docType, tenantId)
        const newDraft = await svc.saveDraft(id, { title: data.title ?? null, slug, data }, user?.userId)
        // saveDraft always returns an unpublished draft; sync against the root's published row.
        const pub = await db.prepare("SELECT id FROM documents WHERE root_id = ? AND is_published = 1 AND tenant_id = ?").bind(id, tenantId).first() as any
        if (status === 'published') await svc.publish(newDraft.id, user?.userId)
        else if (pub) await svc.unpublish(pub.id)

        await getCacheService(CACHE_CONFIGS.content!).invalidate(`content:list:*`)
        const redirectUrl = `/admin/content/${id}/edit?success=Content updated successfully!`
        return c.req.header('HX-Request') === 'true'
          ? c.text('', 200, { 'HX-Redirect': redirectUrl })
          : c.redirect(redirectUrl)
      }
    }

    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Content not found.
      </div>
    `, 404)

    // Get existing content
    const contentStmt = db.prepare('SELECT * FROM content WHERE id = ?')
    const existingContent = await contentStmt.bind(id).first() as any

    if (!existingContent) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Content not found.
        </div>
      `)
    }

    const collection = await getCollection(db, existingContent.collection_id)
    if (!collection) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Collection not found.
        </div>
      `)
    }

    const fields = await getCollectionFields(db, existingContent.collection_id)

    // Extract and validate field data
    const { data, errors } = extractFieldData(fields, formData)

    if (Object.keys(errors).length > 0) {
      const formDataWithErrors: ContentFormData = {
        id,
        collection: collection!,
        fields,
        data,
        validationErrors: errors,
        error: 'Please fix the validation errors below.',
        isEdit: true,
        user: user ? {
          name: user!.email,
          email: user!.email,
          role: user!.role
        } : undefined
      }
      if (c.req.header('HX-Request') === 'true') {
        c.header('HX-Retarget', '#content-form-page')
        c.header('HX-Reswap', 'outerHTML')
        return c.html(renderContentFormPage(formDataWithErrors, { partialOnly: true }))
      }
      return c.html(renderContentFormPage(formDataWithErrors))
    }

    // Update slug if title changed
    let slug = data.slug || data.title
    if (slug) {
      slug = slug.toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .trim('-')
    }

    // Determine status
    let status = formData.get('status') as string || existingContent.status
    if (action === 'save_and_publish') {
      status = 'published'
    }

    // Handle scheduling
    const scheduledPublishAt = formData.get('scheduled_publish_at') as string
    const scheduledUnpublishAt = formData.get('scheduled_unpublish_at') as string

    // Update content
    const now = Date.now()

    const updateStmt = db.prepare(`
      UPDATE content SET
        slug = ?, title = ?, data = ?, status = ?,
        scheduled_publish_at = ?, scheduled_unpublish_at = ?,
        meta_title = ?, meta_description = ?, updated_at = ?
      WHERE id = ?
    `)

    await updateStmt.bind(
      slug,
      data.title || 'Untitled',
      JSON.stringify(data),
      status,
      scheduledPublishAt ? new Date(scheduledPublishAt).getTime() : null,
      scheduledUnpublishAt ? new Date(scheduledUnpublishAt).getTime() : null,
      data.meta_title || null,
      data.meta_description || null,
      now,
      id
    ).run()

    // Invalidate content cache
    const cache = getCacheService(CACHE_CONFIGS.content!)
    await cache.delete(cache.generateKey('content', id))
    await cache.invalidate(`content:list:${existingContent.collection_id}:*`)

    // Create new version if content changed
    const existingData = JSON.parse(existingContent.data || '{}')
    if (JSON.stringify(existingData) !== JSON.stringify(data)) {
      // Get next version number
      const versionCountStmt = db.prepare('SELECT MAX(version) as max_version FROM content_versions WHERE content_id = ?')
      const versionResult = await versionCountStmt.bind(id).first() as any
      const nextVersion = (versionResult?.max_version || 0) + 1

      const versionStmt = db.prepare(`
        INSERT INTO content_versions (id, content_id, version, data, author_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `)

      await versionStmt.bind(
        crypto.randomUUID(),
        id,
        nextVersion,
        JSON.stringify(data),
        user?.userId || 'unknown',
        now
      ).run()
    }

    // Log workflow action if status changed
    if (status !== existingContent.status) {
      const workflowStmt = db.prepare(`
        INSERT INTO workflow_history (id, content_id, action, from_status, to_status, user_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)

      await workflowStmt.bind(
        crypto.randomUUID(),
        id,
        'status_changed',
        existingContent.status,
        status,
        user?.userId || 'unknown',
        now
      ).run()
    }

    const redirectUrl = `/admin/content/${id}/edit?success=Content updated successfully!`

    // Check if this is an HTMX request
    const isHTMX = c.req.header('HX-Request') === 'true'

    if (isHTMX) {
      return c.text('', 200, { 'HX-Redirect': redirectUrl })
    } else {
      return c.redirect(redirectUrl)
    }

  } catch (error) {
    console.error('Error updating content:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Failed to update content. Please try again.
      </div>
    `)
  }
})

// Content preview
adminContentRoutes.post('/preview', requireRole(['admin', 'editor', 'author']), async (c) => {
  try {
    const formData = await c.req.formData()
    const collectionId = formData.get('collection_id') as string

    const db = c.env.DB
    const collection = await getCollection(db, collectionId)

    if (!collection) {
      return c.html('<p>Collection not found</p>')
    }

    const fields = await getCollectionFields(db, collectionId)

    // Extract field data for preview (skip validation)
    const { data } = extractFieldData(fields, formData, { skipValidation: true })

    // Sanitize user-controlled values before rendering
    const safeTitle = escapeHtml(data.title || 'Untitled')
    const safeStatus = escapeHtml(String(formData.get('status') || 'draft'))
    const safeMetaDesc = data.meta_description ? escapeHtml(data.meta_description) : ''
    const safeContent = data.content ? sanitizeRichText(data.content) : '<p>No content provided.</p>'

    // Generate preview HTML
    const previewHTML = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Preview: ${safeTitle}</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
          h1 { color: #333; }
          .meta { color: #666; font-size: 14px; margin-bottom: 20px; }
          .content { line-height: 1.6; }
        </style>
      </head>
      <body>
        <h1>${safeTitle}</h1>
        <div class="meta">
          <strong>Collection:</strong> ${escapeHtml(collection.display_name)}<br>
          <strong>Status:</strong> ${safeStatus}<br>
          ${safeMetaDesc ? `<strong>Description:</strong> ${safeMetaDesc}<br>` : ''}
        </div>
        <div class="content">
          ${safeContent}
        </div>

        <h3>All Fields:</h3>
        <table border="1" style="border-collapse: collapse; width: 100%;">
          <tr><th>Field</th><th>Value</th></tr>
          ${fields.map(field => `
            <tr>
              <td><strong>${escapeHtml(field.field_label)}</strong></td>
              <td>${data[field.field_name] ? escapeHtml(String(data[field.field_name])) : '<em>empty</em>'}</td>
            </tr>
          `).join('')}
        </table>
      </body>
      </html>
    `

    return c.html(previewHTML)
  } catch (error) {
    console.error('Error generating preview:', error)
    return c.html('<p>Error generating preview</p>')
  }
})

// Duplicate content
adminContentRoutes.post('/duplicate', async (c) => {
  try {
    const user = c.get('user')
    const formData = await c.req.formData()
    const originalId = formData.get('id') as string

    if (!originalId) {
      return c.json({ success: false, error: 'Content ID required' })
    }

    const db = c.env.DB

    const tenantId = reqTenant(c)
    const docOriginal = await db
      .prepare("SELECT * FROM documents WHERE root_id = ? AND is_current_draft = 1 AND tenant_id = ? AND deleted_at IS NULL")
      .bind(originalId, tenantId)
      .first() as any
    if (docOriginal) {
      const docType = await getDocBackingType(db, docOriginal.type_id)
      if (docType) {
        const svc = makeDocService(db, docType, tenantId)
        const originalData = docOriginal.data ? JSON.parse(docOriginal.data) : {}
        const copyData = {
          ...originalData,
          title: `${originalData.title || docOriginal.title || 'Untitled'} (Copy)`
        }
        const copy = await svc.create(createDocumentSchema.parse({
          typeId: docType.id,
          tenantId,
          locale: 'default',
          title: copyData.title,
          slug: `${docOriginal.slug || 'copy'}-copy-${Date.now()}`,
          data: copyData,
          publishOnCreate: false,
        }), user?.userId)
        return c.json({ success: true, id: copy.rootId })
      }
    }

    return c.json({ success: false, error: 'Content not found' }, 404)

    // Get original content
    const contentStmt = db.prepare('SELECT * FROM content WHERE id = ?')
    const original = await contentStmt.bind(originalId).first() as any

    if (!original) {
      return c.json({ success: false, error: 'Content not found' })
    }

    // Create duplicate
    const newId = crypto.randomUUID()
    const now = Date.now()
    const originalData = JSON.parse(original.data || '{}')

    // Modify title to indicate it's a copy
    originalData.title = `${originalData.title || 'Untitled'} (Copy)`

    const insertStmt = db.prepare(`
      INSERT INTO content (
        id, collection_id, slug, title, data, status,
        author_id, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)

    await insertStmt.bind(
      newId,
      original.collection_id,
      `${original.slug}-copy-${Date.now()}`,
      originalData.title,
      JSON.stringify(originalData),
      'draft', // Always start as draft
      user?.userId || 'unknown',
      now,
      now
    ).run()

    return c.json({ success: true, id: newId })
  } catch (error) {
    console.error('Error duplicating content:', error)
    return c.json({ success: false, error: 'Failed to duplicate content' })
  }
})

// Get bulk actions modal
adminContentRoutes.get('/bulk-actions', async (c) => {
  const bulkActionsModal = `
    <div class="fixed inset-0 bg-zinc-950/50 dark:bg-zinc-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4" onclick="this.remove()">
      <div class="bg-white dark:bg-zinc-900 rounded-xl shadow-xl ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 max-w-md w-full" onclick="event.stopPropagation()">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-lg font-semibold text-zinc-950 dark:text-white">Bulk Actions</h3>
          <button onclick="this.closest('.fixed').remove()" class="text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200">
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>
        <p class="text-sm text-zinc-600 dark:text-zinc-400 mb-4">
          Select items from the table below to perform bulk actions.
        </p>
        <div class="space-y-2">
          <button
            onclick="performBulkAction('publish')"
            class="w-full inline-flex items-center justify-center gap-x-2 px-4 py-2.5 bg-lime-600 dark:bg-lime-500 text-white rounded-lg hover:bg-lime-700 dark:hover:bg-lime-600 transition-colors"
          >
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
            </svg>
            Publish Selected
          </button>
          <button
            onclick="performBulkAction('draft')"
            class="w-full inline-flex items-center justify-center gap-x-2 px-4 py-2.5 bg-zinc-600 dark:bg-zinc-700 text-white rounded-lg hover:bg-zinc-700 dark:hover:bg-zinc-800 transition-colors"
          >
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/>
            </svg>
            Move to Draft
          </button>
          <button
            onclick="performBulkAction('delete')"
            class="w-full inline-flex items-center justify-center gap-x-2 px-4 py-2.5 bg-red-600 dark:bg-red-500 text-white rounded-lg hover:bg-red-700 dark:hover:bg-red-600 transition-colors"
          >
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
            Delete Selected
          </button>
        </div>
      </div>
    </div>
    <script>
      function performBulkAction(action) {
        const selectedIds = Array.from(document.querySelectorAll('input[type="checkbox"].row-checkbox:checked'))
          .map(cb => cb.value)
          .filter(id => id)

        if (selectedIds.length === 0) {
          alert('Please select at least one item')
          return
        }

        const actionText = action === 'publish' ? 'publish' : action === 'draft' ? 'move to draft' : 'delete'
        const confirmed = confirm(\`Are you sure you want to \${actionText} \${selectedIds.length} item(s)?\`)

        if (!confirmed) return

        fetch('/admin/content/bulk-action', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            action: action,
            ids: selectedIds
          })
        })
        .then(res => res.json())
        .then(data => {
          if (data.success) {
            document.querySelector('#bulk-actions-modal .fixed').remove()
            location.reload()
          } else {
            alert('Error: ' + (data.error || 'Unknown error'))
          }
        })
        .catch(err => {
          console.error('Bulk action error:', err)
          alert('Failed to perform bulk action')
        })
      }
    </script>
  `

  return c.html(bulkActionsModal)
})

// Perform bulk action
adminContentRoutes.post('/bulk-action', async (c) => {
  try {
    const user = c.get('user')
    const body = await c.req.json()
    const { action, ids } = body

    if (!action || !ids || ids.length === 0) {
      return c.json({ success: false, error: 'Action and IDs required' })
    }
    if (!['delete', 'publish', 'draft'].includes(action)) {
      return c.json({ success: false, error: 'Invalid action' })
    }

    const db = c.env.DB
    const now = Date.now()

    // D33: bulk ids can be document root ids (doc-backed collections) OR legacy content ids. The old
    // handler only ran `UPDATE content … WHERE id IN (…)`, which silently no-ops on doc rows while still
    // reporting success. Partition the ids and route each set to the correct store.
    const tenantId = reqTenant(c)
    const idPlaceholders = ids.map(() => '?').join(',')
    const { results: docRootRows } = await db
      .prepare(`SELECT DISTINCT root_id, type_id FROM documents WHERE tenant_id = ? AND root_id IN (${idPlaceholders})`)
      .bind(tenantId, ...ids)
      .all()
    const docRoots = (docRootRows || []) as Array<{ root_id: string; type_id: string }>
    const docRootIds = new Set(docRoots.map(r => r.root_id))
    const contentIds = (ids as string[]).filter(id => !docRootIds.has(id))

    // ── Document-backed rows ──────────────────────────────────────────────────
    if (docRoots.length > 0) {
      if (action === 'delete') {
        // Soft-delete every version row of each root (mirror the single-row DELETE). Seconds (D29).
        const nowSec = Math.floor(now / 1000)
        const dph = docRoots.map(() => '?').join(',')
        await db
          .prepare(`UPDATE documents SET deleted_at = ?, updated_at = ? WHERE tenant_id = ? AND root_id IN (${dph})`)
          .bind(nowSec, nowSec, tenantId, ...docRoots.map(r => r.root_id))
          .run()
      } else {
        // publish / draft → run through DocumentsService so the published flag, prev-published
        // demotion and derived rows stay consistent (one row per root).
        for (const root of docRoots) {
          const docType = await getDocBackingType(db, root.type_id)
          if (!docType) continue
          const svc = makeDocService(db, docType, tenantId)
          if (action === 'publish') {
            const draft = await db.prepare("SELECT id FROM documents WHERE root_id = ? AND tenant_id = ? AND is_current_draft = 1").bind(root.root_id, tenantId).first() as any
            if (draft) await svc.publish(draft.id, user?.userId)
          } else {
            const pub = await db.prepare("SELECT id FROM documents WHERE root_id = ? AND tenant_id = ? AND is_published = 1").bind(root.root_id, tenantId).first() as any
            if (pub) await svc.unpublish(pub.id)
          }
        }
      }
    }

    // Legacy `content` rows were removed from the v3 greenfield schema. Unknown/non-document ids are
    // ignored here instead of probing a table that should no longer exist.

    // Invalidate content caches and the public-API filtered caches so both surfaces reflect the change.
    const cache = getCacheService(CACHE_CONFIGS.content!)
    for (const contentId of ids) {
      await cache.delete(cache.generateKey('content', contentId))
    }
    await cache.invalidate('content:list:*')
    const apiCache = getCacheService(CACHE_CONFIGS.api!)
    await apiCache.invalidate('content-filtered:*')
    await apiCache.invalidate('collection-content-filtered:*')

    return c.json({ success: true, count: ids.length })
  } catch (error) {
    console.error('Bulk action error:', error)
    return c.json({ success: false, error: 'Failed to perform bulk action' })
  }
})

// Delete content
adminContentRoutes.delete('/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const db = c.env.DB
    const user = c.get('user')

    // ── Option B: if :id is a document-backed root, soft-delete every version row of the root ──
    const tenantId = reqTenant(c)
    const docDel = await db
      .prepare("SELECT type_id FROM documents WHERE root_id = ? AND tenant_id = ? LIMIT 1")
      .bind(id, tenantId).first() as any
    if (docDel && (await getDocBackingType(db, docDel.type_id))) {
      const now = Math.floor(Date.now() / 1000)
      await db.prepare("UPDATE documents SET deleted_at = ?, updated_at = ? WHERE root_id = ? AND tenant_id = ?").bind(now, now, id, tenantId).run()
      await getCacheService(CACHE_CONFIGS.content!).invalidate('content:list:*')
      return c.html(`
        <div id="content-list" hx-get="/admin/content?model=${docDel.type_id}" hx-trigger="load" hx-swap="outerHTML">
          <div class="flex items-center justify-center p-8"><span class="text-zinc-500">Deleting…</span></div>
        </div>
      `)
    }

    return c.json({ success: false, error: 'Content not found' }, 404)

    // Check if content exists
    const contentStmt = db.prepare('SELECT id, title FROM content WHERE id = ?')
    const content = await contentStmt.bind(id).first() as any

    if (!content) {
      return c.json({ success: false, error: 'Content not found' }, 404)
    }

    // Soft delete by setting status to 'deleted'
    const now = Date.now()
    const deleteStmt = db.prepare(`
      UPDATE content
      SET status = 'deleted', updated_at = ?
      WHERE id = ?
    `)
    await deleteStmt.bind(now, id).run()

    // Invalidate cache
    const cache = getCacheService(CACHE_CONFIGS.content!)
    await cache.delete(cache.generateKey('content', id))
    await cache.invalidate('content:list:*')

    // Return success - let HTMX reload the page
    return c.html(`
      <div id="content-list" hx-get="/admin/content?model=${c.req.query('model') || 'post'}" hx-trigger="load" hx-swap="outerHTML">
        <div class="flex items-center justify-center p-8">
          <div class="text-center">
            <svg class="mx-auto h-12 w-12 text-lime-500 dark:text-lime-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
            </svg>
            <p class="mt-2 text-sm text-zinc-600 dark:text-zinc-400">Content deleted successfully. Refreshing...</p>
          </div>
        </div>
      </div>
    `)
  } catch (error) {
    console.error('Delete content error:', error)
    return c.json({ success: false, error: 'Failed to delete content' }, 500)
  }
})


// Preview specific version
adminContentRoutes.get('/:id/version/:version/preview', requireRole(['admin', 'editor', 'author']), async (c) => {
  try {
    const id = c.req.param('id')
    const version = parseInt(c.req.param('version') || '0')
    const db = c.env.DB

    // Get the specific version
    const versionStmt = db.prepare(`
      SELECT cv.*, c.collection_id, col.display_name as collection_name
      FROM content_versions cv
      JOIN content c ON cv.content_id = c.id
      JOIN collections col ON c.collection_id = col.id
      WHERE cv.content_id = ? AND cv.version = ?
    `)
    const versionData = await versionStmt.bind(id, version).first() as any

    if (!versionData) {
      return c.html('<p>Version not found</p>')
    }

    const data = JSON.parse(versionData.data || '{}')

    // Sanitize user-controlled values before rendering
    const safeTitle = escapeHtml(data.title || 'Untitled')
    const safeContent = data.content ? sanitizeRichText(data.content) : '<p>No content provided.</p>'
    const safeExcerpt = data.excerpt ? escapeHtml(data.excerpt) : ''
    const safeCollectionName = escapeHtml(versionData.collection_name || '')

    // Generate preview HTML
    const previewHTML = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Version ${version} Preview: ${safeTitle}</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
          h1 { color: #333; }
          .meta { color: #666; font-size: 14px; margin-bottom: 20px; padding: 10px; background: #f5f5f5; border-radius: 5px; }
          .content { line-height: 1.6; }
          .version-badge { background: #007cba; color: white; padding: 5px 10px; border-radius: 15px; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="meta">
          <span class="version-badge">Version ${version}</span>
          <strong>Collection:</strong> ${safeCollectionName}<br>
          <strong>Created:</strong> ${new Date(versionData.created_at).toLocaleString()}<br>
          <em>This is a historical version preview</em>
        </div>

        <h1>${safeTitle}</h1>

        <div class="content">
          ${safeContent}
        </div>

        ${safeExcerpt ? `<h3>Excerpt:</h3><p>${safeExcerpt}</p>` : ''}

        <h3>All Field Data:</h3>
        <pre style="background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto;">
${escapeHtml(JSON.stringify(data, null, 2))}
        </pre>
      </body>
      </html>
    `

    return c.html(previewHTML)
  } catch (error) {
    console.error('Error generating version preview:', error)
    return c.html('<p>Error generating preview</p>')
  }
})

// ═══════════════════════════════════════════════════════════════════════════════
// DOCUMENT MODEL ROUTES  (/admin/content/documents/:typeId/...)
// Document-backed content types managed within the existing content admin.
// Edit links in the content list use id = "documents/:typeId/:rootId" which
// maps to these routes via the existing /:id/edit handler (see redirect below).
// ═══════════════════════════════════════════════════════════════════════════════

function userCtx(c: any) {
  const u = c.get('user')
  return u ? { name: u.email, email: u.email, role: u.role } : undefined
}

function parseDocFormData(
  formData: FormData,
  queryableFields: QueryableField[] = [],
): { title: string | null; slug: string | null; data: Record<string, unknown> } {
  const title = (formData.get('title') as string | null) || null
  const slug = (formData.get('slug') as string | null) || null
  // Facet fields are ALWAYS arrays (D16) — a single value like 'homepage' has no comma but must still
  // become ['homepage'] so document_facets materializes it. Field-kind drives this, not comma-sniffing.
  const facetNames = new Set(queryableFields.filter(f => f.kind === 'facet').map(f => f.name))
  const data: Record<string, unknown> = {}
  for (const [key, val] of formData.entries()) {
    if (key.startsWith('data[') && key.endsWith(']')) {
      const fieldName = key.slice(5, -1)
      const strVal = val as string
      if (facetNames.has(fieldName)) {
        data[fieldName] = strVal.split(',').map(s => s.trim()).filter(Boolean)
      } else if (strVal.includes(',') && !strVal.startsWith('{')) {
        data[fieldName] = strVal.split(',').map(s => s.trim()).filter(Boolean)
      } else if (strVal === 'true') { data[fieldName] = true }
      else if (strVal === 'false') { data[fieldName] = false }
      else if (strVal !== '' && !isNaN(Number(strVal)) && strVal.trim() !== '') { data[fieldName] = Number(strVal) }
      else { data[fieldName] = strVal }
    }
  }
  return { title, slug, data }
}

async function getDocService(db: D1Database, typeId: string, tenantId: string) {
  const registry = new DocumentTypeRegistry(db)
  const docType = await registry.findById(typeId)
  const svc = new DocumentsService(db, {
    queryableFields: docType?.queryableFields ?? [],
    typeSchemaVersion: docType?.schemaVersion ?? 1,
    maxVersionsPerRoot: docType?.settings?.maxVersionsPerRoot ?? 50,
    tenantId,
    versioning: docType?.settings?.versioning ?? false,
  })
  return { svc, docType }
}

// ─── New document form ────────────────────────────────────────────────────────
adminContentRoutes.get('/documents/:typeId/new', async (c) => {
  const { typeId } = c.req.param()
  const registry = new DocumentTypeRegistry(c.env.DB)
  const docType = await registry.findById(typeId)
  if (!docType) return c.html('<p>Unknown document type.</p>', 404)
  return c.html(renderDocumentFormPage({ docType, isEdit: false, user: userCtx(c) }))
})

// ─── Create document ──────────────────────────────────────────────────────────
adminContentRoutes.post('/documents/:typeId/new', async (c) => {
  const { typeId } = c.req.param()
  const db = c.env.DB
  const user = c.get('user') as any
  try {
    const tenantId = reqTenant(c)
    const { svc, docType } = await getDocService(db, typeId, tenantId)
    if (!docType) return c.html('<p>Unknown document type.</p>', 404)
    const formData = await c.req.formData()
    const { title, slug, data } = parseDocFormData(formData, docType.queryableFields)
    const doc = await svc.create(createDocumentSchema.parse({
      typeId, tenantId, locale: 'default',
      title: title ?? undefined, slug: slug ?? undefined, data,
    }), user?.userId)
    return c.redirect(`/admin/content/documents/${typeId}/${doc.rootId}/edit?message=Created+successfully`)
  } catch (err: any) {
    const registry = new DocumentTypeRegistry(c.env.DB)
    const docType = await registry.findById(typeId)
    if (!docType) return c.html('<p>Unknown document type.</p>', 404)
    return c.html(renderDocumentFormPage({ docType, isEdit: false, user: userCtx(c), message: err?.message ?? 'Failed to create', messageType: 'error' }))
  }
})

// ─── Edit document form ───────────────────────────────────────────────────────
adminContentRoutes.get('/documents/:typeId/:rootId/edit', async (c) => {
  const { typeId, rootId } = c.req.param()
  const db = c.env.DB
  const message = c.req.query('message')
  const registry = new DocumentTypeRegistry(db)
  const docType = await registry.findById(typeId)
  if (!docType) return c.html('<p>Unknown document type.</p>', 404)

  const tenantId = reqTenant(c)
  const draftRow = await db.prepare(
    'SELECT * FROM documents WHERE root_id = ? AND tenant_id = ? AND is_current_draft = 1'
  ).bind(rootId, tenantId).first() as any
  if (!draftRow) return c.html('<p>Document not found.</p>', 404)

  let publishedDoc = null
  if (!draftRow.is_published) {
    const pubRow = await db.prepare(
      'SELECT * FROM documents WHERE root_id = ? AND tenant_id = ? AND is_published = 1'
    ).bind(rootId, tenantId).first() as any
    if (pubRow) publishedDoc = { id: pubRow.id, rootId: pubRow.root_id, typeId: pubRow.type_id, versionNumber: pubRow.version_number, isCurrentDraft: false, isPublished: true, status: pubRow.status, data: JSON.parse(pubRow.data ?? '{}') } as any
  }

  const doc = {
    id: draftRow.id, rootId: draftRow.root_id, typeId: draftRow.type_id, typeVersion: draftRow.type_version,
    versionOfId: draftRow.version_of_id, versionNumber: draftRow.version_number,
    isCurrentDraft: draftRow.is_current_draft === 1, isPublished: draftRow.is_published === 1, status: draftRow.status,
    parentRootId: draftRow.parent_root_id, slug: draftRow.slug, path: draftRow.path, title: draftRow.title,
    zone: draftRow.zone, sortOrder: draftRow.sort_order, visible: draftRow.visible === 1,
    publishedAt: draftRow.published_at, scheduledAt: draftRow.scheduled_at, expiresAt: draftRow.expires_at,
    deletedAt: draftRow.deleted_at, tenantId: draftRow.tenant_id, locale: draftRow.locale,
    translationGroupId: draftRow.translation_group_id, data: JSON.parse(draftRow.data ?? '{}'),
    metadata: JSON.parse(draftRow.metadata ?? '{}'), ownerId: draftRow.owner_id,
    createdBy: draftRow.created_by, updatedBy: draftRow.updated_by,
    createdAt: draftRow.created_at, updatedAt: draftRow.updated_at,
  } as any

  return c.html(renderDocumentFormPage({ docType, doc, publishedDoc, isEdit: true, message, user: userCtx(c), versioningEnabled: docType?.settings?.versioning === true }))
})

// ─── Save draft ───────────────────────────────────────────────────────────────
adminContentRoutes.post('/documents/:typeId/:rootId', async (c) => {
  const { typeId, rootId } = c.req.param()
  const db = c.env.DB
  const user = c.get('user') as any
  try {
    const formData = await c.req.formData()
    const _method = formData.get('_method') as string | null
    if (_method !== 'PUT') return c.redirect(`/admin/content/documents/${typeId}/${rootId}/edit?message=Unknown+action`)
    const { svc, docType } = await getDocService(db, typeId, reqTenant(c))
    const { title, slug, data } = parseDocFormData(formData, docType?.queryableFields ?? [])
    await svc.saveDraft(rootId, { title, slug, data }, user?.userId)
    return c.redirect(`/admin/content/documents/${typeId}/${rootId}/edit?message=Draft+saved`)
  } catch (err: any) {
    return c.redirect(`/admin/content/documents/${typeId}/${rootId}/edit?message=${encodeURIComponent(err?.message ?? 'Save failed')}`)
  }
})

// ─── Publish ──────────────────────────────────────────────────────────────────
adminContentRoutes.post('/documents/:typeId/:documentId/publish', async (c) => {
  const { typeId, documentId } = c.req.param()
  const db = c.env.DB
  const user = c.get('user') as any
  try {
    const tenantId = reqTenant(c)
    const row = await db.prepare('SELECT root_id FROM documents WHERE id = ? AND tenant_id = ?').bind(documentId, tenantId).first() as any
    const { svc } = await getDocService(db, typeId, tenantId)
    await svc.publish(documentId, user?.userId)
    return c.redirect(`/admin/content/documents/${typeId}/${row?.root_id}/edit?message=Published`)
  } catch (err: any) {
    return c.redirect(`/admin/content?model=doc:${typeId}&message=${encodeURIComponent(err?.message ?? 'Publish failed')}`)
  }
})

// ─── Unpublish ────────────────────────────────────────────────────────────────
adminContentRoutes.post('/documents/:typeId/:documentId/unpublish', async (c) => {
  const { typeId, documentId } = c.req.param()
  const db = c.env.DB
  try {
    const tenantId = reqTenant(c)
    const row = await db.prepare('SELECT root_id FROM documents WHERE id = ? AND tenant_id = ?').bind(documentId, tenantId).first() as any
    const { svc } = await getDocService(db, typeId, tenantId)
    await svc.unpublish(documentId)
    return c.redirect(`/admin/content/documents/${typeId}/${row?.root_id}/edit?message=Unpublished`)
  } catch (err: any) {
    return c.redirect(`/admin/content?model=doc:${typeId}&message=${encodeURIComponent(err?.message ?? 'Unpublish failed')}`)
  }
})

// ─── Delete (soft) ────────────────────────────────────────────────────────────
adminContentRoutes.post('/documents/:typeId/:documentId/delete', async (c) => {
  const { typeId, documentId } = c.req.param()
  const db = c.env.DB
  try {
    const tenantId = reqTenant(c)
    const { svc, docType } = await getDocService(db, typeId, tenantId)
    if (docType?.settings?.pii) {
      const row = await db.prepare('SELECT root_id FROM documents WHERE id = ? AND tenant_id = ?').bind(documentId, tenantId).first() as any
      if (row) await svc.erase(row.root_id, tenantId)
    } else {
      await svc.softDelete(documentId)
    }
    return c.redirect(`/admin/content?model=doc:${typeId}&message=Deleted`)
  } catch (err: any) {
    return c.redirect(`/admin/content?model=doc:${typeId}&message=${encodeURIComponent(err?.message ?? 'Delete failed')}`)
  }
})

// ─── Version history fragment (HTMX) ─────────────────────────────────────────
adminContentRoutes.get('/documents/:typeId/:rootId/versions', async (c) => {
  const { typeId, rootId } = c.req.param()
  const db = c.env.DB
  const { renderVersionHistoryFragment } = await import('../templates/pages/admin-documents-form.template')
  const registry = new DocumentTypeRegistry(db)
  const docType = await registry.findById(typeId)
  if (!docType) return c.html('<div>Unknown type.</div>', 404)
  const result = await db.prepare(
    'SELECT id, version_number, is_current_draft, is_published, status, updated_at, created_by FROM documents WHERE root_id = ? AND tenant_id = ? ORDER BY version_number DESC LIMIT 50'
  ).bind(rootId, reqTenant(c)).all()
  const versions = (result.results ?? []).map((r: any) => ({
    id: r.id, versionNumber: r.version_number, isCurrentDraft: r.is_current_draft === 1,
    isPublished: r.is_published === 1, status: r.status, updatedAt: r.updated_at, createdBy: r.created_by,
  }))
  return c.html(renderVersionHistoryFragment({ versions, docType, rootId }))
})

// The content list sets item.id = "documents/:typeId/:rootId", so the rendered edit link is
// /admin/content/documents/:typeId/:rootId/edit — served by the GET handler above. No catch-all is
// needed here (removed a stale comment that promised one but defined nothing — D14).

export default adminContentRoutes
