import { Hono } from 'hono'
import { requireAuth } from '../middleware'
import { renderFormsListPage } from '../templates/pages/admin-forms-list.template'
import { renderFormBuilderPage, type FormBuilderPageData } from '../templates/pages/admin-forms-builder.template'
import { renderFormCreatePage } from '../templates/pages/admin-forms-create.template'
import { TurnstileService } from '../plugins/core-plugins/turnstile-plugin/services/turnstile'
import { syncFormCollection } from '../services/form-collection-sync'

// Type definitions for forms
interface Form {
  id: string
  name: string
  display_name: string
  description?: string
  category: string
  submission_count: number
  is_active: boolean
  is_public: boolean
  created_at: number
  updated_at: number
  formattedDate: string
}

interface FormData {
  id?: string
  name?: string
  display_name?: string
  description?: string
  category?: string
  formio_schema?: any
  settings?: any
  is_active?: boolean
  is_public?: boolean
  google_maps_api_key?: string
  turnstile_site_key?: string
  error?: string
  success?: string
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

interface FormsListPageData {
  forms: Form[]
  search?: string
  category?: string
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
  ENVIRONMENT?: string
  GOOGLE_MAPS_API_KEY?: string
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

export const adminFormsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware
adminFormsRoutes.use('*', requireAuth())

// Forms management - List all forms
adminFormsRoutes.get('/', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const search = c.req.query('search') || ''
    const category = c.req.query('category') || ''

    // Build query
    let query = 'SELECT * FROM forms WHERE 1=1'
    const params: string[] = []

    if (search) {
      query += ' AND (name LIKE ? OR display_name LIKE ?)'
      params.push(`%${search}%`, `%${search}%`)
    }

    if (category) {
      query += ' AND category = ?'
      params.push(category)
    }

    query += ' ORDER BY created_at DESC'

    const result = await db.prepare(query).bind(...params).all()

    // Format dates
    const forms = result.results.map((form: any) => ({
      ...form,
      formattedDate: new Date(form.created_at).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      })
    }))

    const pageData: FormsListPageData = {
      forms,
      search,
      category,
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined,
      version: c.get('appVersion')
    }

    return c.html(renderFormsListPage(pageData))
  } catch (error: any) {
    console.error('Error listing forms:', error)
    return c.html('<p>Error loading forms</p>', 500)
  }
})

// Show create form page
adminFormsRoutes.get('/new', async (c) => {
  try {
    const user = c.get('user')

    const pageData: FormData = {
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined,
      version: c.get('appVersion')
    }

    return c.html(renderFormCreatePage(pageData))
  } catch (error: any) {
    console.error('Error showing create form page:', error)
    return c.html('<p>Error loading form</p>', 500)
  }
})

// Show docs page
adminFormsRoutes.get('/docs', async (c) => {
  try {
    const user = c.get('user')
    const { renderFormsDocsPage } = await import('../templates/index.js')

    const pageData = {
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined,
      version: c.get('appVersion')
    }

    return c.html(renderFormsDocsPage(pageData))
  } catch (error: any) {
    console.error('Error showing forms docs page:', error)
    return c.html('<p>Error loading documentation</p>', 500)
  }
})

// Show examples page
adminFormsRoutes.get('/examples', async (c) => {
  try {
    const user = c.get('user')
    const { renderFormsExamplesPage } = await import('../templates/index.js')

    const pageData = {
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined,
      version: c.get('appVersion')
    }

    return c.html(renderFormsExamplesPage(pageData))
  } catch (error: any) {
    console.error('Error showing forms examples page:', error)
    return c.html('<p>Error loading examples</p>', 500)
  }
})

// Create new form
adminFormsRoutes.post('/', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const body = await c.req.parseBody()

    const name = body.name as string
    const displayName = body.displayName as string
    const description = (body.description as string) || ''
    const category = (body.category as string) || 'general'

    // Validate required fields
    if (!name || !displayName) {
      return c.json({ error: 'Name and display name are required' }, 400)
    }

    // Validate name format (lowercase, numbers, underscores only)
    if (!/^[a-z0-9_]+$/.test(name)) {
      return c.json({ 
        error: 'Form name must contain only lowercase letters, numbers, and underscores' 
      }, 400)
    }

    // Check for duplicate name
    const existing = await db.prepare('SELECT id FROM forms WHERE name = ?')
      .bind(name)
      .first()

    if (existing) {
      return c.json({ error: 'A form with this name already exists' }, 400)
    }

    // Create form with empty schema
    const formId = crypto.randomUUID()
    const now = Date.now()
    const emptySchema = { components: [] } // Empty Form.io schema

    await db.prepare(`
      INSERT INTO forms (
        id, name, display_name, description, category,
        formio_schema, settings, is_active, is_public,
        created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      formId,
      name,
      displayName,
      description,
      category,
      JSON.stringify(emptySchema),
      JSON.stringify({
        submitButtonText: 'Submit',
        successMessage: 'Thank you for your submission!',
        requireAuth: false,
        emailNotifications: false
      }),
      1, // is_active
      1, // is_public
      user?.userId || null,
      now,
      now
    ).run()

    // Create shadow collection for this form
    try {
      await syncFormCollection(db, {
        id: formId,
        name,
        display_name: displayName,
        description,
        formio_schema: emptySchema,
        is_active: 1
      })
    } catch (syncError) {
      console.error('[AdminForms] Error syncing form collection on create:', syncError)
    }

    // Redirect to builder
    return c.redirect(`/admin/forms/${formId}/builder`)
  } catch (error: any) {
    console.error('Error creating form:', error)
    return c.json({ error: 'Failed to create form' }, 500)
  }
})

// Show form builder
adminFormsRoutes.get('/:id/builder', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const formId = c.req.param('id')
    const googleMapsApiKey = c.env.GOOGLE_MAPS_API_KEY || ''

    // Get form
    const form = await db.prepare('SELECT * FROM forms WHERE id = ?')
      .bind(formId)
      .first()

    if (!form) {
      return c.html('<p>Form not found</p>', 404)
    }

    // Get Turnstile configuration
    const turnstileService = new TurnstileService(db)
    const turnstileSettings = await turnstileService.getSettings()

    const pageData: FormData = {
      id: form.id as string,
      name: form.name as string,
      display_name: form.display_name as string,
      description: form.description as string | undefined,
      category: form.category as string,
      formio_schema: form.formio_schema ? JSON.parse(form.formio_schema as string) : { components: [] },
      settings: form.settings ? JSON.parse(form.settings as string) : {},
      is_active: Boolean(form.is_active),
      is_public: Boolean(form.is_public),
      google_maps_api_key: googleMapsApiKey,
      turnstile_site_key: turnstileSettings?.siteKey || '',
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined,
      version: c.get('appVersion')
    }

    return c.html(renderFormBuilderPage(pageData as FormBuilderPageData))
  } catch (error: any) {
    console.error('Error showing form builder:', error)
    return c.html('<p>Error loading form builder</p>', 500)
  }
})

// Update form (save schema)
adminFormsRoutes.put('/:id', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const formId = c.req.param('id')
    const body = await c.req.json()

    // Check if form exists
    const form = await db.prepare('SELECT id, name, display_name, description, is_active FROM forms WHERE id = ?')
      .bind(formId)
      .first()

    if (!form) {
      return c.json({ error: 'Form not found' }, 404)
    }

    const now = Date.now()

    // Update form schema
    await db.prepare(`
      UPDATE forms
      SET formio_schema = ?,
          updated_by = ?,
          updated_at = ?
      WHERE id = ?
    `).bind(
      JSON.stringify(body.formio_schema),
      user?.userId || null,
      now,
      formId
    ).run()

    // Optionally update turnstile settings
    if (body.turnstile_enabled !== undefined || body.turnstile_settings !== undefined) {
      const updates: string[] = []
      const values: any[] = []

      if (body.turnstile_enabled !== undefined) {
        updates.push('turnstile_enabled = ?')
        values.push(body.turnstile_enabled ? 1 : 0)
      }
      if (body.turnstile_settings !== undefined) {
        updates.push('turnstile_settings = ?')
        values.push(JSON.stringify(body.turnstile_settings))
      }

      if (updates.length > 0) {
        values.push(formId)
        await db.prepare(`UPDATE forms SET ${updates.join(', ')} WHERE id = ?`)
          .bind(...values)
          .run()
      }
    }

    // Update shadow collection schema
    try {
      await syncFormCollection(db, {
        id: form.id as string,
        name: form.name as string,
        display_name: form.display_name as string,
        description: form.description as string | null,
        formio_schema: body.formio_schema,
        is_active: form.is_active as number
      })
    } catch (syncError) {
      console.error('[AdminForms] Error syncing form collection on update:', syncError)
    }

    return c.json({ success: true, message: 'Form saved successfully' })
  } catch (error: any) {
    console.error('Error updating form:', error)
    return c.json({ error: 'Failed to save form' }, 500)
  }
})

// Delete form
adminFormsRoutes.delete('/:id', async (c) => {
  try {
    const db = c.env.DB
    const formId = c.req.param('id')

    // Check if form exists
    const form = await db.prepare('SELECT id, submission_count FROM forms WHERE id = ?')
      .bind(formId)
      .first()

    if (!form) {
      return c.json({ error: 'Form not found' }, 404)
    }

    // Warn if form has submissions
    const submissionCount = form.submission_count as number || 0
    if (submissionCount > 0) {
      return c.json({ 
        error: `Cannot delete form with ${submissionCount} submissions. Archive it instead.` 
      }, 400)
    }

    // Delete form (cascade will delete submissions and files)
    await db.prepare('DELETE FROM forms WHERE id = ?').bind(formId).run()

    return c.json({ success: true, message: 'Form deleted successfully' })
  } catch (error: any) {
    console.error('Error deleting form:', error)
    return c.json({ error: 'Failed to delete form' }, 500)
  }
})

// View form submissions — redirect to unified content listing
adminFormsRoutes.get('/:id/submissions', async (c) => {
  try {
    const db = c.env.DB
    const formId = c.req.param('id')

    // Get form name to build redirect URL
    const form = await db.prepare('SELECT name FROM forms WHERE id = ?')
      .bind(formId)
      .first()

    if (!form) {
      return c.html('<p>Form not found</p>', 404)
    }

    // Redirect to content listing filtered by form collection
    return c.redirect(`/admin/content?model=form_${form.name}`)
  } catch (error: any) {
    console.error('Error loading submissions:', error)
    return c.html('<p>Error loading submissions</p>', 500)
  }
})

export default adminFormsRoutes
