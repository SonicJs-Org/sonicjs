import { Hono } from 'hono'
import { html } from 'hono/html'
import { requireAuth, requireRole } from '../middleware'
import { isPluginActive } from '../middleware/plugin-middleware'
import { normalizeFieldType } from './admin-collections-field-types'
import { renderCollectionsListPage } from '../templates/pages/admin-collections-list.template'
import { renderCollectionFormPage } from '../templates/pages/admin-collections-form.template'
import { loadCollectionConfigs } from '../services/collection-loader'

// Type definitions for collections
interface Collection {
  id: string
  name: string
  display_name: string
  description?: string
  created_at: number
  formattedDate: string
  field_count?: number
  managed?: boolean
  source_type?: string | null
}

interface CollectionFormData {
  id?: string
  name?: string
  display_name?: string
  description?: string
  fields?: CollectionField[]
  managed?: boolean
  isEdit?: boolean
  error?: string
  success?: string
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
  editorPlugins?: {
    tinymce: boolean
    quill: boolean
    easyMdx: boolean
  }
}

interface CollectionField {
  id: string
  field_name: string
  field_type: string
  field_label: string
  field_options: any
  field_order: number
  is_required: boolean
  is_searchable: boolean
}

interface CollectionsListPageData {
  collections: Collection[]
  search?: string
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

type Bindings = {
  DB: D1Database
  CACHE_KV: KVNamespace
  MEDIA_BUCKET: R2Bucket
  ASSETS: Fetcher
  EMAIL_QUEUE?: Queue
  SENDGRID_API_KEY?: string
  DEFAULT_FROM_EMAIL?: string
  IMAGES_ACCOUNT_ID?: string
  IMAGES_API_TOKEN?: string
  ENVIRONMENT?: string
}

type Variables = {
  user?: {
    userId: string
    email: string
    role: string
    exp: number
    iat: number
  }
  requestId?: string
  startTime?: number
  appVersion?: string
}

export const adminCollectionsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware
adminCollectionsRoutes.use('*', requireAuth())

// Enforce admin-only access on collection modification routes
adminCollectionsRoutes.post('*', requireRole(['admin']))
adminCollectionsRoutes.put('*', requireRole(['admin']))
adminCollectionsRoutes.delete('*', requireRole(['admin']))

// Collections management - List all collections
adminCollectionsRoutes.get('/', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const url = new URL(c.req.url)
    const search = url.searchParams.get('search') || ''

    // Build query based on search
    let stmt
    let results
    if (search) {
      stmt = db.prepare(`
        SELECT id, name, display_name, description, created_at, schema, source, queryable_fields
        FROM document_types
        WHERE is_active = 1
        AND (name LIKE ? OR display_name LIKE ? OR description LIKE ?)
        ORDER BY created_at DESC
      `)
      const searchParam = `%${search}%`
      const queryResults = await stmt.bind(searchParam, searchParam, searchParam).all()
      results = queryResults.results
    } else {
      stmt = db.prepare("SELECT id, name, display_name, description, created_at, schema, source, queryable_fields FROM document_types WHERE is_active = 1 ORDER BY created_at DESC")
      const queryResults = await stmt.all()
      results = queryResults.results
    }

    // Load code-defined collections
    const codeCollections = await loadCollectionConfigs()

    // Convert code collections to Collection type
    const codeCollectionsMap = new Map(
      codeCollections.map((cfg: any) => {
        const fieldCount = cfg.schema?.properties ? Object.keys(cfg.schema.properties).length : 0
        return [cfg.name, {
          id: cfg.name,
          name: cfg.name,
          display_name: cfg.displayName,
          description: cfg.description,
          created_at: 0,
          formattedDate: 'Code-defined',
          field_count: fieldCount,
          managed: cfg.managed !== false,
          source_type: 'code'
        } as Collection]
      })
    )

    // Convert database results to Collection type
    const dbCollections: Collection[] = (results || [])
      .filter((row: any) => row && row.id)
      .map((row: any) => {
        // Calculate field count from schema
        let fieldCount = 0
        if (row.schema) {
          try {
            const schema = typeof row.schema === 'string' ? JSON.parse(row.schema) : row.schema
            if (schema && schema.properties) {
              fieldCount = Object.keys(schema.properties).length
            }
          } catch (e) {
            console.error('Error parsing schema for document type:', row.id, e)
          }
        }

        // Also count queryable fields for document model types
        if (fieldCount === 0 && row.queryable_fields) {
          try {
            const qf = typeof row.queryable_fields === 'string' ? JSON.parse(row.queryable_fields) : row.queryable_fields
            if (Array.isArray(qf)) fieldCount = qf.length
          } catch (e) {}
        }

        return {
          id: String(row.id || ''),
          name: String(row.name || ''),
          display_name: String(row.display_name || ''),
          description: row.description ? String(row.description) : undefined,
          created_at: Number(row.created_at || 0),
          formattedDate: row.created_at ? new Date(Number(row.created_at)).toLocaleDateString() : 'Unknown',
          field_count: fieldCount,
          managed: false,
          source_type: (row.source === 'code' || row.source === 'system' || row.source === 'plugin') ? 'code' : 'user'
        }
      })

    // Merge: database collections + code collections (code ownership wins for same name)
    const mergedMap = new Map(codeCollectionsMap)
    dbCollections.forEach(collection => {
      const codeCollection = codeCollectionsMap.get(collection.name)
      mergedMap.set(collection.name, codeCollection ? {
        ...collection,
        display_name: codeCollection.display_name,
        description: codeCollection.description,
        field_count: codeCollection.field_count,
        managed: true,
        source_type: 'code',
        formattedDate: 'Code-defined'
      } : collection)
    })

    // Apply search filter if present
    let collections = Array.from(mergedMap.values())
    if (search) {
      const searchLower = search.toLowerCase()
      collections = collections.filter(c =>
        c.name.toLowerCase().includes(searchLower) ||
        c.display_name.toLowerCase().includes(searchLower) ||
        (c.description && c.description.toLowerCase().includes(searchLower))
      )
    }

    const pageData: CollectionsListPageData = {
      collections,
      search,
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined,
      version: c.get('appVersion')
    }

    return c.html(renderCollectionsListPage(pageData))
  } catch (error) {
    console.error('Error fetching collections:', error)
    const errorMessage = error instanceof Error ? error.message : String(error)
    return c.html(html`<p>Error loading collections: ${errorMessage}</p>`)
  }
})

// New collection form
adminCollectionsRoutes.get('/new', async (c) => {
  const user = c.get('user')
  const db = c.env.DB

  // Check which editor plugins are active
  const [tinymceActive, quillActive, mdxeditorActive] = await Promise.all([
    isPluginActive(db, 'tinymce-plugin'),
    isPluginActive(db, 'quill-editor'),
    isPluginActive(db, 'easy-mdx')
  ])

  console.log('[Collections /new] Editor plugins status:', {
    tinymce: tinymceActive,
    quill: quillActive,
    easyMdx: mdxeditorActive
  })

  const formData: CollectionFormData = {
    isEdit: false,
    user: user ? {
      name: user.email,
      email: user.email,
      role: user.role
    } : undefined,
    version: c.get('appVersion'),
    editorPlugins: {
      tinymce: tinymceActive,
      quill: quillActive,
      easyMdx: mdxeditorActive
    }
  }

  return c.html(renderCollectionFormPage(formData))
})

// Create collection
adminCollectionsRoutes.post('/', async (c) => {
  try {
    const formData = await c.req.formData()
    const name = formData.get('name') as string
    const displayName = formData.get('displayName') as string
    const description = formData.get('description') as string

    // Check if this is an HTMX request
    const isHtmx = c.req.header('HX-Request') === 'true'

    // Basic validation
    if (!name || !displayName) {
      const errorMsg = 'Name and display name are required.'
      if (isHtmx) {
        return c.html(html`
          <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
            ${errorMsg}
          </div>
        `)
      } else {
        // For regular form submission, redirect back with error
        return c.redirect('/admin/collections/new')
      }
    }

    // Validate name format
    if (!/^[a-z0-9_]+$/.test(name)) {
      const errorMsg = 'Collection name must contain only lowercase letters, numbers, and underscores.'
      if (isHtmx) {
        return c.html(html`
          <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
            ${errorMsg}
          </div>
        `)
      } else {
        return c.redirect('/admin/collections/new')
      }
    }

    const db = c.env.DB

    // Check if document type already exists
    const existingStmt = db.prepare('SELECT id FROM document_types WHERE name = ?')
    const existing = await existingStmt.bind(name).first()

    if (existing) {
      const errorMsg = 'A collection with this name already exists.'
      if (isHtmx) {
        return c.html(html`
          <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
            ${errorMsg}
          </div>
        `)
      } else {
        return c.redirect('/admin/collections/new')
      }
    }

    // Create basic schema for the document type
    const basicSchema = {
      type: "object",
      properties: {
        title: {
          type: "string",
          title: "Title"
        },
        content: {
          type: "string",
          title: "Content",
          format: "richtext"
        }
      },
      required: ["title"]
    }

    // Create document type
    const typeId = crypto.randomUUID()
    const now = Math.floor(Date.now() / 1000) // unixepoch

    const insertStmt = db.prepare(`
      INSERT INTO document_types (id, name, display_name, description, schema, is_active, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)

    await insertStmt.bind(
      typeId,
      name,
      displayName,
      description || null,
      JSON.stringify(basicSchema),
      1, // is_active
      now,
      now
    ).run()

    // Clear cache (only if CACHE_KV is available)
    if (c.env.CACHE_KV) {
      try {
        await c.env.CACHE_KV.delete('cache:collections:all')
        await c.env.CACHE_KV.delete(`cache:collection:${name}`)
      } catch (e) {
        console.error('Error clearing cache:', e)
      }
    }

    if (isHtmx) {
      return c.html(html`
        <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
          Collection created successfully! Redirecting to edit mode...
          <script>
            setTimeout(() => {
              window.location.href = '/admin/collections/${typeId}';
            }, 1500);
          </script>
        </div>
      `)
    } else {
      // For regular form submission, redirect to edit page
      return c.redirect(`/admin/collections/${typeId}`)
    }
  } catch (error) {
    console.error('Error creating collection:', error)
    const isHtmx = c.req.header('HX-Request') === 'true'

    if (isHtmx) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Failed to create collection. Please try again.
        </div>
      `)
    } else {
      return c.redirect('/admin/collections/new')
    }
  }
})

// Edit collection form
adminCollectionsRoutes.get('/:id', async (c) => {
  const db = c.env.DB
  try {
    const id = c.req.param('id')
    const user = c.get('user')

    const stmt = db.prepare('SELECT * FROM document_types WHERE id = ?')
    const collection = await stmt.bind(id).first() as any

    if (!collection) {
      // Check which editor plugins are active
      const [tinymceActive, quillActive, mdxeditorActive] = await Promise.all([
        isPluginActive(db, 'tinymce-plugin'),
        isPluginActive(db, 'quill-editor'),
        isPluginActive(db, 'easy-mdx')
      ])

      const formData: CollectionFormData = {
        isEdit: true,
        error: 'Collection not found.',
        user: user ? {
          name: user.email,
          email: user.email,
          role: user.role
        } : undefined,
        version: c.get('appVersion'),
        editorPlugins: {
          tinymce: tinymceActive,
          quill: quillActive,
          easyMdx: mdxeditorActive
        }
      }
      return c.html(renderCollectionFormPage(formData))
    }

    // Get collection fields - try schema first, then content_fields table
    let fields: CollectionField[] = []

    // If collection has a schema, parse it
    if (collection.schema) {
      try {
        const schema = typeof collection.schema === 'string' ? JSON.parse(collection.schema) : collection.schema
        if (schema && schema.properties) {
          // Convert schema properties to field format
          let fieldOrder = 0
          fields = Object.entries(schema.properties).map(([fieldName, fieldConfig]: [string, any]) => {
            // Normalize schema formats to UI field types
            let fieldType = fieldConfig.type || 'string'
            if (fieldConfig.enum) {
              fieldType = 'select'
            } else if (fieldConfig.format === 'richtext') {
              fieldType = 'richtext'
            } else if (fieldConfig.format === 'media') {
              fieldType = 'media'
            } else if (fieldConfig.format === 'date-time') {
              fieldType = 'date'
            } else if (fieldConfig.type === 'slug' || fieldConfig.format === 'slug') {
              fieldType = 'slug'
            }
            
            return {
              id: `schema-${fieldName}`,
              field_name: fieldName,
              field_type: fieldType,
              field_label: fieldConfig.title || fieldName,
              field_options: fieldConfig,
              field_order: fieldOrder++,
              is_required: fieldConfig.required === true || (schema.required && schema.required.includes(fieldName)),
              is_searchable: fieldConfig.searchable === true || false
            }
          })
        }
      } catch (e) {
        console.error('Error parsing collection schema:', e)
      }
    }

    // If no fields from DB schema, fall back to code-defined collection config
    // (e.g. blog_post is registered via registerCollections with a full field schema,
    // but its document_types entry uses a passthrough Zod schema with no .properties)
    let isCodeDriven = false
    if (fields.length === 0) {
      try {
        const codeCollections = await loadCollectionConfigs()
        const codeCol = codeCollections.find((c) => c.name === id || c.name === collection.name)
        if (codeCol?.schema?.properties) {
          let fieldOrder = 0
          fields = Object.entries(codeCol.schema.properties).map(([fieldName, fieldConfig]: [string, any]) => {
            let fieldType = fieldConfig.type || 'string'
            if (fieldConfig.enum) {
              fieldType = 'select'
            } else if (fieldConfig.format === 'richtext') {
              fieldType = 'richtext'
            } else if (fieldConfig.format === 'media') {
              fieldType = 'media'
            } else if (fieldConfig.format === 'date-time') {
              fieldType = 'date'
            } else if (fieldConfig.type === 'slug' || fieldConfig.format === 'slug') {
              fieldType = 'slug'
            }
            return {
              id: `schema-${fieldName}`,
              field_name: fieldName,
              field_type: fieldType,
              field_label: fieldConfig.title || fieldName,
              field_options: fieldConfig,
              field_order: fieldOrder++,
              is_required: fieldConfig.required === true || !!(codeCol.schema.required && (codeCol.schema.required as string[]).includes(fieldName)),
              is_searchable: fieldConfig.searchable === true || false
            }
          })
          isCodeDriven = true
        }
      } catch (e) {
        console.error('Error loading code collection config:', e)
      }
    }

    // Check which editor plugins are active
    const [tinymceActive, quillActive, mdxeditorActive] = await Promise.all([
      isPluginActive(db, 'tinymce-plugin'),
      isPluginActive(db, 'quill-editor'),
      isPluginActive(db, 'easy-mdx')
    ])

    console.log('[Collections /:id] Editor plugins status:', {
      tinymce: tinymceActive,
      quill: quillActive,
      easyMdx: mdxeditorActive
    })

    const formData: CollectionFormData = {
      id: collection.id,
      name: collection.name,
      display_name: collection.display_name,
      description: collection.description,
      fields: fields,
      managed: collection.managed === 1 || isCodeDriven,
      isEdit: true,
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined,
      version: c.get('appVersion'),
      editorPlugins: {
        tinymce: tinymceActive,
        quill: quillActive,
        easyMdx: mdxeditorActive
      }
    }

    return c.html(renderCollectionFormPage(formData))
  } catch (error) {
    console.error('Error fetching collection:', error)
    const user = c.get('user')

    // Check which editor plugins are active (even in error state)
    const [tinymceActive, quillActive, mdxeditorActive] = await Promise.all([
      isPluginActive(db, 'tinymce-plugin'),
      isPluginActive(db, 'quill-editor'),
      isPluginActive(db, 'easy-mdx')
    ])

    const formData: CollectionFormData = {
      isEdit: true,
      error: 'Failed to load collection.',
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined,
      version: c.get('appVersion'),
      editorPlugins: {
        tinymce: tinymceActive,
        quill: quillActive,
        easyMdx: mdxeditorActive
      }
    }
    return c.html(renderCollectionFormPage(formData))
  }
})

// Update collection
adminCollectionsRoutes.put('/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const formData = await c.req.formData()
    const displayName = formData.get('displayName') as string
    const description = formData.get('description') as string

    if (!displayName) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Display name is required.
        </div>
      `)
    }

    const db = c.env.DB

    const updateStmt = db.prepare(`
      UPDATE document_types
      SET display_name = ?, description = ?, updated_at = ?
      WHERE id = ?
    `)

    const now = Math.floor(Date.now() / 1000) // unixepoch
    await updateStmt.bind(displayName, description || null, now, id).run()

    return c.html(html`
      <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded">
        Collection updated successfully!
      </div>
    `)
  } catch (error) {
    console.error('Error updating collection:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Failed to update collection. Please try again.
      </div>
    `)
  }
})

// Delete collection
adminCollectionsRoutes.delete('/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const db = c.env.DB

    const typeStmt = db.prepare('SELECT name FROM document_types WHERE id = ?')
    const docType = await typeStmt.bind(id).first() as any

    if (!docType) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Document type not found.
        </div>
      `)
    }

    // Check if document type has documents
    const contentStmt = db.prepare("SELECT COUNT(DISTINCT root_id) as count FROM documents WHERE type_id = ?")
    const contentResult = await contentStmt.bind(id).first() as any

    if (contentResult && contentResult.count > 0) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Cannot delete document type: it contains ${contentResult.count} document(s). Delete all documents first.
        </div>
      `)
    }

    // Delete document type
    const deleteStmt = db.prepare('DELETE FROM document_types WHERE id = ?')
    await deleteStmt.bind(id).run()

    return c.html(html`
      <script>
        window.location.href = '/admin/collections';
      </script>
    `)
  } catch (error) {
    console.error('Error deleting collection:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Failed to delete collection. Please try again.
      </div>
    `)
  }
})

// Add field to collection
adminCollectionsRoutes.post('/:id/fields', async (c) => {
  try {
    const collectionId = c.req.param('id')
    const formData = await c.req.formData()
    const fieldName = formData.get('field_name') as string
    const fieldType = formData.get('field_type') as string
    const fieldLabel = formData.get('field_label') as string
    const isRequired = formData.get('is_required') === '1'
    const isSearchable = formData.get('is_searchable') === '1'
    const fieldOptions = formData.get('field_options') as string || '{}'

    if (!fieldName || !fieldType || !fieldLabel) {
      return c.json({ success: false, error: 'Field name, type, and label are required.' })
    }

    // Validate field name format
    if (!/^[a-z0-9_]+$/.test(fieldName)) {
      return c.json({ success: false, error: 'Field name must contain only lowercase letters, numbers, and underscores.' })
    }

    const db = c.env.DB

    // Get current document type to check its schema
    const getCollectionStmt = db.prepare('SELECT * FROM document_types WHERE id = ?')
    const collection = await getCollectionStmt.bind(collectionId).first() as any

    if (!collection) {
      return c.json({ success: false, error: 'Collection not found.' })
    }

    // Check if field already exists in schema
    let schema = collection.schema ? (typeof collection.schema === 'string' ? JSON.parse(collection.schema) : collection.schema) : null

    if (schema && schema.properties && schema.properties[fieldName]) {
      return c.json({ success: false, error: 'A field with this name already exists.' })
    }

    // Parse field options
    let parsedOptions = {}
    try {
      parsedOptions = fieldOptions ? JSON.parse(fieldOptions) : {}
    } catch (e) {
      console.error('Error parsing field options:', e)
    }

    // Add field to schema (primary storage method)
    if (schema) {
      if (!schema.properties) {
        schema.properties = {}
      }
      if (!schema.required) {
        schema.required = []
      }

      // Build field config based on type
      const fieldConfig: any = {
        type: fieldType === 'number' ? 'number' : fieldType === 'boolean' ? 'boolean' : 'string',
        title: fieldLabel,
        searchable: isSearchable,
        ...parsedOptions
      }

      const normalizedFieldType = normalizeFieldType(fieldType)

      // Handle special field types
      if (normalizedFieldType === 'richtext') {
        fieldConfig.format = 'richtext'
      } else if (normalizedFieldType === 'date') {
        fieldConfig.format = 'date-time'
      } else if (normalizedFieldType === 'select') {
        fieldConfig.enum = (parsedOptions as any).options || []
      } else if (fieldType === 'radio') {
        fieldConfig.type = 'radio'
        if (!(parsedOptions as any).enum && (parsedOptions as any).options) {
          fieldConfig.enum = (parsedOptions as any).options
        }
      } else if (fieldType === 'media') {
        fieldConfig.format = 'media'
      } else if (normalizedFieldType === 'slug') {
        fieldConfig.type = 'slug'
        fieldConfig.format = 'slug'
      } else if (normalizedFieldType === 'quill') {
        fieldConfig.type = 'quill'
      } else if (normalizedFieldType === 'markdown') {
        fieldConfig.type = 'markdown'
      } else if (normalizedFieldType === 'reference') {
        fieldConfig.type = 'reference'
      }

      schema.properties[fieldName] = fieldConfig

      // Add to required array if needed
      if (isRequired && !schema.required.includes(fieldName)) {
        schema.required.push(fieldName)
      }

      // Update document type schema in database
      const updateSchemaStmt = db.prepare(`
        UPDATE document_types
        SET schema = ?, updated_at = ?
        WHERE id = ?
      `)

      const now = Math.floor(Date.now() / 1000) // unixepoch
      await updateSchemaStmt.bind(JSON.stringify(schema), now, collectionId).run()

      console.log('[Add Field] Added field to schema:', fieldName, fieldConfig)

      return c.json({ success: true, fieldId: `schema-${fieldName}` })
    }

    // All new fields must be part of schema
    return c.json({ success: false, error: 'Cannot add field without schema.' })
  } catch (error) {
    console.error('Error adding field:', error)
    return c.json({ success: false, error: 'Failed to add field.' })
  }
})

// Update field
adminCollectionsRoutes.put('/:collectionId/fields/:fieldId', async (c) => {
  try {
    const fieldId = c.req.param('fieldId')
    const collectionId = c.req.param('collectionId')
    const formData = await c.req.formData()
    const fieldLabel = formData.get('field_label') as string
    const fieldType = formData.get('field_type') as string
    // Use getAll() to handle hidden input + checkbox pattern (get last value)
    const isRequiredValues = formData.getAll('is_required')
    const isSearchableValues = formData.getAll('is_searchable')
    const isRequired = isRequiredValues[isRequiredValues.length - 1] === '1'
    const isSearchable = isSearchableValues[isSearchableValues.length - 1] === '1'
    const fieldOptions = formData.get('field_options') as string || '{}'

    // Log all form data for debugging
    console.log('[Field Update] Field ID:', fieldId)
    console.log('[Field Update] Form data received:', {
      field_label: fieldLabel,
      field_type: fieldType,
      is_required: formData.get('is_required'),
      is_searchable: formData.get('is_searchable'),
      field_options: fieldOptions
    })

    if (!fieldLabel) {
      return c.json({ success: false, error: 'Field label is required.' })
    }

    const db = c.env.DB

    // Check if this is a schema field (starts with "schema-")
    if (fieldId.startsWith('schema-')) {
      // Schema fields are part of the collection's JSON schema
      // We need to update the collection's schema in the database
      const fieldName = fieldId.replace('schema-', '')

      console.log('[Field Update] Updating schema field:', fieldName)

      // Get the current document type
      const getCollectionStmt = db.prepare('SELECT * FROM document_types WHERE id = ?')
      const collection = await getCollectionStmt.bind(collectionId).first()

      if (!collection) {
        return c.json({ success: false, error: 'Collection not found.' })
      }

      // Parse the current schema
      let schema = typeof collection.schema === 'string' ? JSON.parse(collection.schema) : collection.schema
      if (!schema) {
        schema = { type: 'object', properties: {}, required: [] }
      }
      if (!schema.properties) {
        schema.properties = {}
      }
      if (!schema.required) {
        schema.required = []
      }

      // Update the field in the schema
      if (schema.properties[fieldName]) {
        // Parse field options from form
        let parsedFieldOptions: Record<string, any> = {}
        try {
          parsedFieldOptions = JSON.parse(fieldOptions)
        } catch (e) {
          console.error('[Field Update] Error parsing field options:', e)
        }

        // Build the updated field config - merge in field options
        const updatedFieldConfig: any = {
          ...schema.properties[fieldName],
          ...parsedFieldOptions,
          type: fieldType,
          title: fieldLabel,
          searchable: isSearchable
        }

        // Also set/remove the individual required property on the field
        // This ensures consistency regardless of which format is checked in GET
        if (isRequired) {
          updatedFieldConfig.required = true
        } else {
          delete updatedFieldConfig.required
        }

        schema.properties[fieldName] = updatedFieldConfig

        // Handle required field in the schema's required array (proper JSON Schema way)
        const requiredIndex = schema.required.indexOf(fieldName)
        console.log('[Field Update] Required field handling:', {
          fieldName,
          isRequired,
          currentRequiredArray: schema.required,
          requiredIndex
        })

        if (isRequired && requiredIndex === -1) {
          // Add to required array if checked and not already there
          schema.required.push(fieldName)
          console.log('[Field Update] Added field to required array')
        } else if (!isRequired && requiredIndex !== -1) {
          // Remove from required array if unchecked and currently there
          schema.required.splice(requiredIndex, 1)
          console.log('[Field Update] Removed field from required array')
        }

        console.log('[Field Update] Final required array:', schema.required)
        console.log('[Field Update] Final field config:', schema.properties[fieldName])
      }

      // Update the document type in the database
      const updateCollectionStmt = db.prepare(`
        UPDATE document_types
        SET schema = ?, updated_at = ?
        WHERE id = ?
      `)

      const now = Math.floor(Date.now() / 1000) // unixepoch
      const result = await updateCollectionStmt.bind(JSON.stringify(schema), now, collectionId).run()

      console.log('[Field Update] Schema update result:', {
        success: result.success,
        changes: result.meta?.changes
      })

      return c.json({ success: true })
    }

    // All fields in new model must be schema-based
    return c.json({ success: false, error: 'Field not found.' })
  } catch (error) {
    console.error('Error updating field:', error)
    return c.json({ success: false, error: 'Failed to update field.' })
  }
})

// Delete field
adminCollectionsRoutes.delete('/:collectionId/fields/:fieldId', async (c) => {
  try {
    const fieldId = c.req.param('fieldId')
    const collectionId = c.req.param('collectionId')
    const db = c.env.DB

    // Check if this is a schema field (starts with "schema-")
    if (fieldId.startsWith('schema-')) {
      const fieldName = fieldId.replace('schema-', '')

      // Get the current document type
      const getCollectionStmt = db.prepare('SELECT * FROM document_types WHERE id = ?')
      const collection = await getCollectionStmt.bind(collectionId).first() as any

      if (!collection) {
        return c.json({ success: false, error: 'Collection not found.' })
      }

      // Parse the current schema
      let schema = typeof collection.schema === 'string' ? JSON.parse(collection.schema) : collection.schema
      if (!schema || !schema.properties) {
        return c.json({ success: false, error: 'Field not found in schema.' })
      }

      // Remove field from schema
      if (schema.properties[fieldName]) {
        delete schema.properties[fieldName]

        // Also remove from required array if present
        if (schema.required && Array.isArray(schema.required)) {
          const requiredIndex = schema.required.indexOf(fieldName)
          if (requiredIndex !== -1) {
            schema.required.splice(requiredIndex, 1)
          }
        }

        // Update the document type in the database
        const updateCollectionStmt = db.prepare(`
          UPDATE document_types
          SET schema = ?, updated_at = ?
          WHERE id = ?
        `)

        const now = Math.floor(Date.now() / 1000) // unixepoch
        await updateCollectionStmt.bind(JSON.stringify(schema), now, collectionId).run()

        console.log('[Delete Field] Removed field from schema:', fieldName)

        return c.json({ success: true })
      } else {
        return c.json({ success: false, error: 'Field not found in schema.' })
      }
    }

    // All fields in new model must be schema-based
    return c.json({ success: false, error: 'Field not found.' })
  } catch (error) {
    console.error('Error deleting field:', error)
    return c.json({ success: false, error: 'Failed to delete field.' })
  }
})

// Update field order
adminCollectionsRoutes.post('/:collectionId/fields/reorder', async (c) => {
  try {
    const body = await c.req.json()
    const fieldOrder = body.fieldOrder as Record<string, number>

    if (!fieldOrder || typeof fieldOrder !== 'object') {
      return c.json({ success: false, error: 'Invalid field order data.' })
    }

    const db = c.env.DB
    const collectionId = c.req.param('collectionId')

    // Get current document type
    const getStmt = db.prepare('SELECT * FROM document_types WHERE id = ?')
    const docType = await getStmt.bind(collectionId).first() as any

    if (!docType) {
      return c.json({ success: false, error: 'Document type not found.' })
    }

    // Parse schema and reorder properties
    let schema = typeof docType.schema === 'string' ? JSON.parse(docType.schema) : docType.schema
    if (!schema || !schema.properties) {
      return c.json({ success: false, error: 'No schema properties found.' })
    }

    // Rebuild properties in new order
    const newProperties: Record<string, any> = {}
    Object.keys(fieldOrder).forEach(fieldName => {
      if (schema.properties[fieldName]) {
        newProperties[fieldName] = schema.properties[fieldName]
      }
    })
    // Add any fields not in fieldOrder
    Object.keys(schema.properties).forEach(fieldName => {
      if (!newProperties[fieldName]) {
        newProperties[fieldName] = schema.properties[fieldName]
      }
    })
    schema.properties = newProperties

    // Update schema
    const updateStmt = db.prepare('UPDATE document_types SET schema = ?, updated_at = ? WHERE id = ?')
    const now = Math.floor(Date.now() / 1000) // unixepoch
    await updateStmt.bind(JSON.stringify(schema), now, collectionId).run()

    return c.json({ success: true })
  } catch (error) {
    console.error('Error reordering fields:', error)
    return c.json({ success: false, error: 'Failed to reorder fields.' })
  }
})
