import { Hono } from 'hono'
import { html } from 'hono/html'
import { requireAuth } from '../middleware'
import { isPluginActive } from '../middleware/plugin-middleware'
import { renderCollectionsListPage } from '../templates/pages/admin-collections-list.template'
import { renderCollectionFormPage } from '../templates/pages/admin-collections-form.template'

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
        SELECT id, name, display_name, description, created_at, managed, schema
        FROM collections
        WHERE is_active = 1
        AND (name LIKE ? OR display_name LIKE ? OR description LIKE ?)
        ORDER BY created_at DESC
      `)
      const searchParam = `%${search}%`
      const queryResults = await stmt.bind(searchParam, searchParam, searchParam).all()
      results = queryResults.results
    } else {
      stmt = db.prepare('SELECT id, name, display_name, description, created_at, managed, schema FROM collections WHERE is_active = 1 ORDER BY created_at DESC')
      const queryResults = await stmt.all()
      results = queryResults.results
    }

    // Fetch field counts for all collections from content_fields table (legacy)
    const fieldCountStmt = db.prepare('SELECT collection_id, COUNT(*) as count FROM content_fields GROUP BY collection_id')
    const { results: fieldCountResults } = await fieldCountStmt.all()
    const fieldCounts = new Map((fieldCountResults || []).map((row: any) => [String(row.collection_id), Number(row.count)]))

    const collections: Collection[] = (results || [])
      .filter((row: any) => row && row.id)
      .map((row: any) => {
        // Calculate field count: use schema if available, otherwise use content_fields table
        let fieldCount = 0
        if (row.schema) {
          try {
            const schema = typeof row.schema === 'string' ? JSON.parse(row.schema) : row.schema
            if (schema && schema.properties) {
              fieldCount = Object.keys(schema.properties).length
            }
          } catch (e) {
            // If schema parsing fails, fall back to content_fields count
            fieldCount = fieldCounts.get(String(row.id)) || 0
          }
        } else {
          fieldCount = fieldCounts.get(String(row.id)) || 0
        }

        return {
          id: String(row.id || ''),
          name: String(row.name || ''),
          display_name: String(row.display_name || ''),
          description: row.description ? String(row.description) : undefined,
          created_at: Number(row.created_at || 0),
          formattedDate: row.created_at ? new Date(Number(row.created_at)).toLocaleDateString() : 'Unknown',
          field_count: fieldCount,
          managed: row.managed === 1
        }
      })

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

    // Check if collection already exists
    const existingStmt = db.prepare('SELECT id FROM collections WHERE name = ?')
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

    // Create basic schema for the collection
    const basicSchema = {
      type: "object",
      properties: {
        title: {
          type: "string",
          title: "Title",
          required: true
        },
        content: {
          type: "string",
          title: "Content",
          format: "richtext"
        },
        status: {
          type: "string",
          title: "Status",
          enum: ["draft", "published", "archived"],
          default: "draft"
        }
      },
      required: ["title"]
    }

    // Create collection
    const collectionId = crypto.randomUUID()
    const now = Date.now()

    const insertStmt = db.prepare(`
      INSERT INTO collections (id, name, display_name, description, schema, is_active, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)

    await insertStmt.bind(
      collectionId,
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
              window.location.href = '/admin/collections/${collectionId}';
            }, 1500);
          </script>
        </div>
      `)
    } else {
      // For regular form submission, redirect to edit page
      return c.redirect(`/admin/collections/${collectionId}`)
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

    const stmt = db.prepare('SELECT * FROM collections WHERE id = ?')
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

    // Fall back to content_fields table if no schema or parsing failed
    if (fields.length === 0) {
      const fieldsStmt = db.prepare(`
        SELECT * FROM content_fields
        WHERE collection_id = ?
        ORDER BY field_order ASC
      `)
      const { results: fieldsResults } = await fieldsStmt.bind(id).all()
      fields = (fieldsResults || []).map((row: any) => {
        let fieldOptions = {}
        if (row.field_options) {
          try {
            fieldOptions = typeof row.field_options === 'string' ? JSON.parse(row.field_options) : row.field_options
          } catch (e) {
            console.error('Error parsing field_options for field:', row.field_name, e)
            fieldOptions = {}
          }
        }
        return {
          id: row.id,
          field_name: row.field_name,
          field_type: row.field_type,
          field_label: row.field_label,
          field_options: fieldOptions,
          field_order: row.field_order,
          is_required: row.is_required === 1,
          is_searchable: row.is_searchable === 1
        }
      })
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
      managed: collection.managed === 1,
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
      UPDATE collections
      SET display_name = ?, description = ?, updated_at = ?
      WHERE id = ?
    `)

    await updateStmt.bind(displayName, description || null, Date.now(), id).run()

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

    // Check if collection has content
    const contentStmt = db.prepare('SELECT COUNT(*) as count FROM content WHERE collection_id = ?')
    const contentResult = await contentStmt.bind(id).first() as any

    if (contentResult && contentResult.count > 0) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Cannot delete collection: it contains ${contentResult.count} content item(s). Delete all content first.
        </div>
      `)
    }

    // Delete collection fields first
    const deleteFieldsStmt = db.prepare('DELETE FROM content_fields WHERE collection_id = ?')
    await deleteFieldsStmt.bind(id).run()

    // Delete collection
    const deleteStmt = db.prepare('DELETE FROM collections WHERE id = ?')
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

    // Get current collection to check its schema
    const getCollectionStmt = db.prepare('SELECT * FROM collections WHERE id = ?')
    const collection = await getCollectionStmt.bind(collectionId).first() as any

    if (!collection) {
      return c.json({ success: false, error: 'Collection not found.' })
    }

    // Check if field already exists in schema
    let schema = collection.schema ? (typeof collection.schema === 'string' ? JSON.parse(collection.schema) : collection.schema) : null

    if (schema && schema.properties && schema.properties[fieldName]) {
      return c.json({ success: false, error: 'A field with this name already exists.' })
    }

    // Also check content_fields table for legacy support
    const existingStmt = db.prepare('SELECT id FROM content_fields WHERE collection_id = ? AND field_name = ?')
    const existing = await existingStmt.bind(collectionId, fieldName).first()

    if (existing) {
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

      // Handle special field types
      if (fieldType === 'richtext') {
        fieldConfig.format = 'richtext'
      } else if (fieldType === 'date') {
        fieldConfig.format = 'date-time'
      } else if (fieldType === 'select') {
        fieldConfig.enum = (parsedOptions as any).options || []
      } else if (fieldType === 'radio') {
        fieldConfig.type = 'radio'
        if (!(parsedOptions as any).enum && (parsedOptions as any).options) {
          fieldConfig.enum = (parsedOptions as any).options
        }
      } else if (fieldType === 'media') {
        fieldConfig.format = 'media'
      } else if (fieldType === 'slug') {
        fieldConfig.type = 'slug'
        fieldConfig.format = 'slug'
      } else if (fieldType === 'quill') {
        fieldConfig.type = 'quill'
      } else if (fieldType === 'mdxeditor') {
        fieldConfig.type = 'mdxeditor'
      } else if (fieldType === 'reference') {
        fieldConfig.type = 'reference'
      }

      schema.properties[fieldName] = fieldConfig

      // Add to required array if needed
      if (isRequired && !schema.required.includes(fieldName)) {
        schema.required.push(fieldName)
      }

      // Update collection schema in database
      const updateSchemaStmt = db.prepare(`
        UPDATE collections
        SET schema = ?, updated_at = ?
        WHERE id = ?
      `)

      await updateSchemaStmt.bind(JSON.stringify(schema), Date.now(), collectionId).run()

      console.log('[Add Field] Added field to schema:', fieldName, fieldConfig)

      return c.json({ success: true, fieldId: `schema-${fieldName}` })
    }

    // Fallback: If no schema exists, use content_fields table
    // Get next field order
    const orderStmt = db.prepare('SELECT MAX(field_order) as max_order FROM content_fields WHERE collection_id = ?')
    const orderResult = await orderStmt.bind(collectionId).first() as any
    const nextOrder = (orderResult?.max_order || 0) + 1

    // Create field in content_fields table
    const fieldId = crypto.randomUUID()
    const now = Date.now()

    const insertStmt = db.prepare(`
      INSERT INTO content_fields (
        id, collection_id, field_name, field_type, field_label,
        field_options, field_order, is_required, is_searchable,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)

    await insertStmt.bind(
      fieldId,
      collectionId,
      fieldName,
      fieldType,
      fieldLabel,
      fieldOptions,
      nextOrder,
      isRequired ? 1 : 0,
      isSearchable ? 1 : 0,
      now,
      now
    ).run()

    return c.json({ success: true, fieldId })
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

      // Get the current collection
      const getCollectionStmt = db.prepare('SELECT * FROM collections WHERE id = ?')
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

      // Update the collection in the database
      const updateCollectionStmt = db.prepare(`
        UPDATE collections
        SET schema = ?, updated_at = ?
        WHERE id = ?
      `)

      const result = await updateCollectionStmt.bind(JSON.stringify(schema), Date.now(), collectionId).run()

      console.log('[Field Update] Schema update result:', {
        success: result.success,
        changes: result.meta?.changes
      })

      return c.json({ success: true })
    }

    // For regular database fields
    const updateStmt = db.prepare(`
      UPDATE content_fields
      SET field_label = ?, field_type = ?, field_options = ?, is_required = ?, is_searchable = ?, updated_at = ?
      WHERE id = ?
    `)

    const result = await updateStmt.bind(fieldLabel, fieldType, fieldOptions, isRequired ? 1 : 0, isSearchable ? 1 : 0, Date.now(), fieldId).run()

    console.log('[Field Update] Update result:', {
      success: result.success,
      meta: result.meta,
      changes: result.meta?.changes,
      last_row_id: result.meta?.last_row_id
    })

    // Verify the update by reading back the field
    const verifyStmt = db.prepare('SELECT * FROM content_fields WHERE id = ?')
    const verifyResult = await verifyStmt.bind(fieldId).first()
    console.log('[Field Update] Verification - field after update:', verifyResult)

    console.log('[Field Update] Successfully updated field with type:', fieldType)

    return c.json({ success: true })
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

      // Get the current collection
      const getCollectionStmt = db.prepare('SELECT * FROM collections WHERE id = ?')
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

        // Update the collection in the database
        const updateCollectionStmt = db.prepare(`
          UPDATE collections
          SET schema = ?, updated_at = ?
          WHERE id = ?
        `)

        await updateCollectionStmt.bind(JSON.stringify(schema), Date.now(), collectionId).run()

        console.log('[Delete Field] Removed field from schema:', fieldName)

        return c.json({ success: true })
      } else {
        return c.json({ success: false, error: 'Field not found in schema.' })
      }
    }

    // For regular database fields
    const deleteStmt = db.prepare('DELETE FROM content_fields WHERE id = ?')
    await deleteStmt.bind(fieldId).run()

    return c.json({ success: true })
  } catch (error) {
    console.error('Error deleting field:', error)
    return c.json({ success: false, error: 'Failed to delete field.' })
  }
})

// Update field order
adminCollectionsRoutes.post('/:collectionId/fields/reorder', async (c) => {
  try {
    const body = await c.req.json()
    const fieldIds = body.fieldIds as string[]

    if (!Array.isArray(fieldIds)) {
      return c.json({ success: false, error: 'Invalid field order data.' })
    }

    const db = c.env.DB

    // Update field order
    for (let i = 0; i < fieldIds.length; i++) {
      const updateStmt = db.prepare('UPDATE content_fields SET field_order = ?, updated_at = ? WHERE id = ?')
      await updateStmt.bind(i + 1, Date.now(), fieldIds[i]).run()
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('Error reordering fields:', error)
    return c.json({ success: false, error: 'Failed to reorder fields.' })
  }
})
