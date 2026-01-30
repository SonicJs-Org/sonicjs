/**
 * Form-Collection Sync Service
 *
 * Bridge logic that creates "shadow collections" for forms and
 * dual-writes form submissions to the content table, enabling
 * unified content management for form submissions.
 */

const SYSTEM_FORM_USER_ID = 'system-form-submission'

/**
 * Convert Form.io component type to collection schema field type
 */
function mapFormioTypeToSchemaType(component: any): { type: string; [key: string]: any } {
  switch (component.type) {
    case 'textfield':
    case 'textarea':
    case 'password':
    case 'phoneNumber':
    case 'url':
      return { type: 'string', title: component.label || component.key }
    case 'email':
      return { type: 'string', format: 'email', title: component.label || component.key }
    case 'number':
    case 'currency':
      return { type: 'number', title: component.label || component.key }
    case 'checkbox':
      return { type: 'boolean', title: component.label || component.key }
    case 'select':
    case 'radio': {
      const enumValues = (component.data?.values || component.values || []).map((v: any) => v.value)
      const enumLabels = (component.data?.values || component.values || []).map((v: any) => v.label)
      return {
        type: 'select',
        title: component.label || component.key,
        enum: enumValues,
        enumLabels
      }
    }
    case 'selectboxes':
      return { type: 'object', title: component.label || component.key }
    case 'datetime':
    case 'day':
    case 'time':
      return { type: 'string', format: 'date-time', title: component.label || component.key }
    case 'file':
    case 'signature':
      return { type: 'string', title: component.label || component.key }
    case 'address':
      return { type: 'object', title: component.label || component.key }
    case 'hidden':
      return { type: 'string', title: component.label || component.key }
    default:
      return { type: 'string', title: component.label || component.key }
  }
}

/**
 * Recursively extract field components from a Form.io schema,
 * skipping layout-only components (panels, columns, fieldsets, etc.)
 */
function extractFieldComponents(components: any[]): any[] {
  const fields: any[] = []
  if (!components) return fields

  for (const comp of components) {
    // Layout components — recurse into children
    if (comp.type === 'panel' || comp.type === 'fieldset' || comp.type === 'well' || comp.type === 'tabs') {
      if (comp.components) {
        fields.push(...extractFieldComponents(comp.components))
      }
      continue
    }
    if (comp.type === 'columns' && comp.columns) {
      for (const col of comp.columns) {
        if (col.components) {
          fields.push(...extractFieldComponents(col.components))
        }
      }
      continue
    }
    if (comp.type === 'table' && comp.rows) {
      for (const row of comp.rows) {
        if (Array.isArray(row)) {
          for (const cell of row) {
            if (cell.components) {
              fields.push(...extractFieldComponents(cell.components))
            }
          }
        }
      }
      continue
    }
    // Skip buttons and non-input layout elements
    if (comp.type === 'button' || comp.type === 'htmlelement' || comp.type === 'content') {
      continue
    }
    // Skip turnstile (not data)
    if (comp.type === 'turnstile') {
      continue
    }
    // It's a real field
    if (comp.key) {
      fields.push(comp)
    }
    // Recurse into sub-components for containers
    if (comp.components) {
      fields.push(...extractFieldComponents(comp.components))
    }
  }
  return fields
}

/**
 * Convert a Form.io schema into a collection JSON schema definition
 */
export function deriveCollectionSchemaFromFormio(formioSchema: any): any {
  const components = formioSchema?.components || []
  const fieldComponents = extractFieldComponents(components)

  const properties: Record<string, any> = {
    // Always include a title field for the content item
    title: { type: 'string', title: 'Title', required: true }
  }
  const required: string[] = ['title']

  for (const comp of fieldComponents) {
    const key = comp.key
    if (!key || key === 'submit' || key === 'title') continue
    const fieldDef = mapFormioTypeToSchemaType(comp)
    if (comp.validate?.required) {
      fieldDef.required = true
      required.push(key)
    }
    properties[key] = fieldDef
  }

  return { type: 'object', properties, required }
}

/**
 * Derive a human-readable title from form submission data
 */
export function deriveSubmissionTitle(data: Record<string, any>, formDisplayName: string): string {
  // Try common fields in order of preference
  const candidates = ['name', 'fullName', 'full_name', 'firstName', 'first_name']
  for (const key of candidates) {
    if (data[key] && typeof data[key] === 'string' && data[key].trim()) {
      // Append last name if available
      if (key === 'firstName' || key === 'first_name') {
        const last = data['lastName'] || data['last_name'] || data['lastname'] || ''
        if (last) return `${data[key].trim()} ${last.trim()}`
      }
      return data[key].trim()
    }
  }
  // Try email
  if (data.email && typeof data.email === 'string' && data.email.trim()) {
    return data.email.trim()
  }
  // Try subject
  if (data.subject && typeof data.subject === 'string' && data.subject.trim()) {
    return data.subject.trim()
  }
  // Fallback
  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  })
  return `${formDisplayName} - ${dateStr}`
}

/**
 * Map form submission status to content status.
 * Form submissions are complete data — they default to 'published'.
 * Only rejected/spam submissions get demoted.
 */
export function mapFormStatusToContentStatus(formStatus: string): string {
  switch (formStatus) {
    case 'pending': return 'published'
    case 'reviewed': return 'published'
    case 'approved': return 'published'
    case 'rejected': return 'archived'
    case 'spam': return 'deleted'
    default: return 'published'
  }
}

/**
 * Create or update a shadow collection for a given form
 */
export async function syncFormCollection(db: D1Database, form: {
  id: string
  name: string
  display_name: string
  description?: string | null
  formio_schema: any
  is_active: number | boolean
}): Promise<{ collectionId: string; status: 'created' | 'updated' | 'unchanged' }> {
  const collectionName = `form_${form.name}`
  const displayName = `${form.display_name} (Form)`

  // Parse formio_schema
  const formioSchema = typeof form.formio_schema === 'string'
    ? JSON.parse(form.formio_schema)
    : form.formio_schema

  const schema = deriveCollectionSchemaFromFormio(formioSchema)
  const schemaJson = JSON.stringify(schema)
  const now = Date.now()
  const isActive = form.is_active ? 1 : 0

  // Check if shadow collection already exists
  const existing = await db.prepare(
    'SELECT id, schema, display_name, description, is_active FROM collections WHERE source_type = ? AND source_id = ?'
  ).bind('form', form.id).first() as any

  if (!existing) {
    // Create new shadow collection
    const collectionId = `col-form-${form.name}-${crypto.randomUUID().slice(0, 8)}`

    await db.prepare(`
      INSERT INTO collections (id, name, display_name, description, schema, is_active, managed, source_type, source_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, 'form', ?, ?, ?)
    `).bind(
      collectionId,
      collectionName,
      displayName,
      form.description || null,
      schemaJson,
      isActive,
      form.id,
      now,
      now
    ).run()

    console.log(`[FormSync] Created shadow collection: ${collectionName}`)
    return { collectionId, status: 'created' }
  }

  // Check if update needed
  const existingSchema = existing.schema ? JSON.stringify(typeof existing.schema === 'string' ? JSON.parse(existing.schema) : existing.schema) : '{}'
  const needsUpdate =
    schemaJson !== existingSchema ||
    displayName !== existing.display_name ||
    (form.description || null) !== existing.description ||
    isActive !== existing.is_active

  if (!needsUpdate) {
    return { collectionId: existing.id, status: 'unchanged' }
  }

  await db.prepare(`
    UPDATE collections SET display_name = ?, description = ?, schema = ?, is_active = ?, updated_at = ?
    WHERE id = ?
  `).bind(
    displayName,
    form.description || null,
    schemaJson,
    isActive,
    now,
    existing.id
  ).run()

  console.log(`[FormSync] Updated shadow collection: ${collectionName}`)
  return { collectionId: existing.id, status: 'updated' }
}

/**
 * Sync all active forms to shadow collections
 */
export async function syncAllFormCollections(db: D1Database): Promise<void> {
  try {
    // Check if forms table exists
    const tableCheck = await db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='forms'"
    ).first()
    if (!tableCheck) {
      console.log('[FormSync] Forms table does not exist, skipping form sync')
      return
    }

    const { results: forms } = await db.prepare(
      'SELECT id, name, display_name, description, formio_schema, is_active FROM forms'
    ).all()

    if (!forms || forms.length === 0) {
      console.log('[FormSync] No forms found, skipping')
      return
    }

    let created = 0
    let updated = 0

    for (const form of forms) {
      try {
        const result = await syncFormCollection(db, form as any)
        if (result.status === 'created') created++
        if (result.status === 'updated') updated++

        // Backfill existing submissions that don't have content_id
        await backfillFormSubmissions(db, form.id as string, result.collectionId)
      } catch (error) {
        console.error(`[FormSync] Error syncing form ${form.name}:`, error)
      }
    }

    console.log(`[FormSync] Sync complete: ${created} created, ${updated} updated out of ${forms.length} forms`)
  } catch (error) {
    console.error('[FormSync] Error syncing form collections:', error)
  }
}

/**
 * Create a content item from a form submission
 */
export async function createContentFromSubmission(
  db: D1Database,
  submissionData: Record<string, any>,
  form: { id: string; name: string; display_name: string },
  submissionId: string,
  metadata: {
    ipAddress?: string | null
    userAgent?: string | null
    userEmail?: string | null
    userId?: string | null
  } = {}
): Promise<string | null> {
  try {
    // Find the shadow collection
    const collection = await db.prepare(
      'SELECT id FROM collections WHERE source_type = ? AND source_id = ?'
    ).bind('form', form.id).first() as any

    if (!collection) {
      console.warn(`[FormSync] No shadow collection found for form ${form.name}`)
      return null
    }

    const contentId = crypto.randomUUID()
    const now = Date.now()

    const title = deriveSubmissionTitle(submissionData, form.display_name)
    const slug = `submission-${submissionId.slice(0, 8)}`

    // Build content data with embedded metadata
    const contentData: Record<string, any> = {
      title,
      ...submissionData,
      _submission_metadata: {
        submissionId,
        formId: form.id,
        formName: form.name,
        email: metadata.userEmail || submissionData.email || null,
        ipAddress: metadata.ipAddress || null,
        userAgent: metadata.userAgent || null,
        submittedAt: now
      }
    }

    const authorId = metadata.userId || SYSTEM_FORM_USER_ID

    await db.prepare(`
      INSERT INTO content (id, collection_id, slug, title, data, status, author_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'published', ?, ?, ?)
    `).bind(
      contentId,
      collection.id,
      slug,
      title,
      JSON.stringify(contentData),
      authorId,
      now,
      now
    ).run()

    // Link submission to content
    await db.prepare(
      'UPDATE form_submissions SET content_id = ? WHERE id = ?'
    ).bind(contentId, submissionId).run()

    return contentId
  } catch (error) {
    console.error('[FormSync] Error creating content from submission:', error)
    return null
  }
}

/**
 * Backfill existing form submissions that don't have a content_id
 */
export async function backfillFormSubmissions(
  db: D1Database,
  formId: string,
  collectionId: string
): Promise<number> {
  try {
    const { results: submissions } = await db.prepare(
      'SELECT id, submission_data, user_email, ip_address, user_agent, user_id, submitted_at FROM form_submissions WHERE form_id = ? AND content_id IS NULL'
    ).bind(formId).all()

    if (!submissions || submissions.length === 0) {
      return 0
    }

    // Get form info
    const form = await db.prepare(
      'SELECT id, name, display_name FROM forms WHERE id = ?'
    ).bind(formId).first() as any

    if (!form) return 0

    let count = 0
    for (const sub of submissions) {
      try {
        const submissionData = typeof sub.submission_data === 'string'
          ? JSON.parse(sub.submission_data as string)
          : sub.submission_data

        const contentId = await createContentFromSubmission(
          db,
          submissionData,
          { id: form.id, name: form.name, display_name: form.display_name },
          sub.id as string,
          {
            ipAddress: sub.ip_address as string | null,
            userAgent: sub.user_agent as string | null,
            userEmail: sub.user_email as string | null,
            userId: sub.user_id as string | null
          }
        )
        if (contentId) count++
      } catch (error) {
        console.error(`[FormSync] Error backfilling submission ${sub.id}:`, error)
      }
    }

    if (count > 0) {
      console.log(`[FormSync] Backfilled ${count} submissions for form ${formId}`)
    }
    return count
  } catch (error) {
    console.error('[FormSync] Error backfilling submissions:', error)
    return 0
  }
}
