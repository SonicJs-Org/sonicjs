/**
 * Admin testimonials routes — backed by the document model (043_document_repository).
 * The legacy `testimonials` table is retained during the POC (the destructive 038 drop was removed).
 * Mounted at /admin/testimonials in app.ts; keeps the same URL paths/templates as before.
 */
import { Hono } from 'hono'
import { z } from 'zod'
import { renderTestimonialsList } from '../templates/pages/admin-testimonials-list.template'
import { renderTestimonialsForm } from '../templates/pages/admin-testimonials-form.template'
import { DocumentsService } from '../services/documents'
import { DocumentTypeRegistry } from '../services/document-type-registry'

type Bindings = { DB: D1Database; KV: KVNamespace }
type Variables = { user?: { userId: string; email: string; role: string; exp: number; iat: number } }

const testimonialSchema = z.object({
  authorName: z.string().min(1, 'Author name is required').max(100),
  authorTitle: z.string().max(100).optional(),
  authorCompany: z.string().max(100).optional(),
  testimonialText: z.string().min(1, 'Testimonial is required').max(1000),
  rating: z.coerce.number().min(1).max(5).optional(),
  isPublished: z.string().default('false').transform(v => v === 'true'),
  sortOrder: z.coerce.number().min(0).default(0),
})

// Map a document row to the shape the list template expects.
function docToListItem(row: any) {
  const data = typeof row.data === 'string' ? JSON.parse(row.data) : (row.data ?? {})
  return {
    id: row.root_id as string,
    author_name: data.authorName ?? '',
    author_title: data.authorTitle,
    author_company: data.authorCompany,
    testimonial_text: data.testimonialText ?? '',
    rating: data.rating,
    isPublished: row.is_published === 1,
    sortOrder: data.sortOrder ?? 0,
    created_at: row.created_at,
    updated_at: row.updated_at,
  }
}

// Map a document row to the shape the form template expects.
function docToFormItem(row: any) {
  const data = typeof row.data === 'string' ? JSON.parse(row.data) : (row.data ?? {})
  return {
    id: row.root_id as string,
    authorName: data.authorName ?? '',
    authorTitle: data.authorTitle,
    authorCompany: data.authorCompany,
    testimonialText: data.testimonialText ?? '',
    rating: data.rating,
    isPublished: row.is_published === 1 || row.isPublished === true,
    sortOrder: data.sortOrder ?? 0,
  }
}

async function getService(db: D1Database) {
  const registry = new DocumentTypeRegistry(db)
  const docType = await registry.findById('testimonial')
  return new DocumentsService(db, {
    queryableFields: docType?.queryableFields ?? [],
    typeSchemaVersion: docType?.schemaVersion ?? 1,
    maxVersionsPerRoot: docType?.settings.maxVersionsPerRoot ?? 50,
  })
}

function userShape(user: any) {
  return user ? { name: user.email, email: user.email, role: user.role } : undefined
}

const adminTestimonialsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// ─── List ─────────────────────────────────────────────────────────────────────
adminTestimonialsRoutes.get('/', async (c) => {
  try {
    const user = c.get('user')
    const db = (c as any).env?.DB as D1Database
    const { published, minRating, search, page = '1' } = c.req.query()
    const currentPage = parseInt(page, 10) || 1
    const limit = 20
    const offset = (currentPage - 1) * limit

    // Build ONE WHERE clause shared by both COUNT and the page query so the total reflects the active
    // filters (D13: previously COUNT ignored published/minRating/search → phantom pages).
    const whereParts: string[] = ['tenant_id = ?', 'type_id = ?', 'is_current_draft = 1', 'deleted_at IS NULL']
    const whereParams: (string | number)[] = ['default', 'testimonial']

    if (published !== undefined) {
      whereParts.push('is_published = ?')
      whereParams.push(published === 'true' ? 1 : 0)
    }
    if (minRating) {
      whereParts.push('q_tst_rating >= ?')
      whereParams.push(parseInt(minRating, 10))
    }
    if (search) {
      whereParts.push(`(json_extract(data,'$.authorName') LIKE ?
               OR json_extract(data,'$.testimonialText') LIKE ?
               OR json_extract(data,'$.authorCompany') LIKE ?)`)
      const term = `%${search}%`
      whereParams.push(term, term, term)
    }
    const whereClause = whereParts.join(' AND ')

    const countResult = await db.prepare(
      `SELECT COUNT(*) as count FROM documents WHERE ${whereClause}`
    ).bind(...whereParams).first() as any
    const totalCount = countResult?.count ?? 0

    // NOTE (D22): this admin HTML list deliberately keeps OFFSET page-number pagination to match the
    // renderTestimonialsList page-number UI. The JSON document APIs use keyset cursors; OFFSET here is
    // an intentional, isolated exception for the rendered admin table, not the public read path.
    const listSql = `SELECT * FROM documents WHERE ${whereClause}
                     ORDER BY q_tst_sort_order ASC, updated_at DESC LIMIT ? OFFSET ?`
    const { results } = await db.prepare(listSql).bind(...whereParams, limit, offset).all()
    const testimonials = (results ?? []).map(docToListItem)

    return c.html(renderTestimonialsList({
      testimonials,
      totalCount,
      currentPage,
      totalPages: Math.ceil(totalCount / limit),
      user: userShape(user),
      message: c.req.query('message'),
    }))
  } catch (error) {
    console.error('Error fetching testimonials:', error)
    const user = c.get('user')
    return c.html(renderTestimonialsList({
      testimonials: [], totalCount: 0, currentPage: 1, totalPages: 1,
      user: userShape(user), message: 'Failed to load testimonials', messageType: 'error',
    }))
  }
})

// ─── New form ─────────────────────────────────────────────────────────────────
adminTestimonialsRoutes.get('/new', async (c) => {
  const user = c.get('user')
  return c.html(renderTestimonialsForm({ isEdit: false, user: userShape(user) }))
})

// ─── Create ───────────────────────────────────────────────────────────────────
adminTestimonialsRoutes.post('/', async (c) => {
  const user = c.get('user')
  const db = (c as any).env?.DB as D1Database
  try {
    const formData = await c.req.formData()
    const validated = testimonialSchema.parse(Object.fromEntries(formData.entries()))

    const svc = await getService(db)
    const doc = await svc.create({
      typeId: 'testimonial', tenantId: 'default', locale: 'default',
      title: validated.authorName,
      sortOrder: validated.sortOrder,
      data: {
        authorName: validated.authorName,
        authorTitle: validated.authorTitle,
        authorCompany: validated.authorCompany,
        testimonialText: validated.testimonialText,
        rating: validated.rating,
        sortOrder: validated.sortOrder,
      },
      parentRootId: '', visible: true, metadata: {}, publishOnCreate: false,
    }, user?.userId)

    if (validated.isPublished) await svc.publish(doc.id, user?.userId)

    return c.redirect('/admin/testimonials?message=Testimonial created successfully')
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errors: Record<string, string[]> = {}
      error.issues.forEach(e => { const f = String(e.path[0]); errors[f] = [...(errors[f] ?? []), e.message] })
      return c.html(renderTestimonialsForm({ isEdit: false, user: userShape(user), errors, message: 'Please correct the errors below', messageType: 'error' }))
    }
    console.error('Error creating testimonial:', error)
    return c.html(renderTestimonialsForm({ isEdit: false, user: userShape(user), message: 'Failed to create testimonial', messageType: 'error' }))
  }
})

// ─── Edit form ────────────────────────────────────────────────────────────────
adminTestimonialsRoutes.get('/:id', async (c) => {
  const user = c.get('user')
  const db = (c as any).env?.DB as D1Database
  try {
    const rootId = c.req.param('id')
    const row = await db.prepare(
      'SELECT * FROM documents WHERE root_id = ? AND tenant_id = ? AND is_current_draft = 1'
    ).bind(rootId, 'default').first()

    if (!row) return c.redirect('/admin/testimonials?message=Testimonial not found&type=error')

    return c.html(renderTestimonialsForm({ testimonial: docToFormItem(row), isEdit: true, user: userShape(user) }))
  } catch (error) {
    console.error('Error fetching testimonial:', error)
    return c.html(renderTestimonialsForm({ isEdit: true, user: userShape(user), message: 'Failed to load testimonial', messageType: 'error' }))
  }
})

// ─── Update ───────────────────────────────────────────────────────────────────
adminTestimonialsRoutes.put('/:id', async (c) => {
  const user = c.get('user')
  const db = (c as any).env?.DB as D1Database
  const rootId = c.req.param('id')
  try {
    const formData = await c.req.formData()
    const validated = testimonialSchema.parse(Object.fromEntries(formData.entries()))

    const svc = await getService(db)
    const newDraft = await svc.saveDraft(rootId, {
      title: validated.authorName,
      sortOrder: validated.sortOrder,
      data: {
        authorName: validated.authorName,
        authorTitle: validated.authorTitle,
        authorCompany: validated.authorCompany,
        testimonialText: validated.testimonialText,
        rating: validated.rating,
        sortOrder: validated.sortOrder,
      },
    }, user?.userId)

    // Sync publish state. saveDraft ALWAYS returns an unpublished draft, so we cannot gate on
    // newDraft.isPublished (it is always false). Act on the root's currently-published row instead.
    const pubRow = await db
      .prepare('SELECT id FROM documents WHERE root_id = ? AND is_published = 1 AND tenant_id = ?')
      .bind(rootId, 'default')
      .first<{ id: string }>()
    if (validated.isPublished) {
      await svc.publish(newDraft.id, user?.userId)
    } else if (pubRow) {
      await svc.unpublish(pubRow.id)
    }

    return c.redirect('/admin/testimonials?message=Testimonial updated successfully')
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errors: Record<string, string[]> = {}
      error.issues.forEach(e => { const f = String(e.path[0]); errors[f] = [...(errors[f] ?? []), e.message] })
      const row = await db.prepare('SELECT * FROM documents WHERE root_id = ? AND is_current_draft = 1').bind(rootId).first()
      return c.html(renderTestimonialsForm({ testimonial: row ? docToFormItem(row) : undefined, isEdit: true, user: userShape(user), errors, message: 'Please correct the errors below', messageType: 'error' }))
    }
    console.error('Error updating testimonial:', error)
    return c.html(renderTestimonialsForm({ isEdit: true, user: userShape(user), message: 'Failed to update testimonial', messageType: 'error' }))
  }
})

// ─── Delete ───────────────────────────────────────────────────────────────────
adminTestimonialsRoutes.delete('/:id', async (c) => {
  const db = (c as any).env?.DB as D1Database
  try {
    const rootId = c.req.param('id')
    // Soft-delete the current draft (the only queryable row for this root).
    const row = await db.prepare('SELECT id FROM documents WHERE root_id = ? AND is_current_draft = 1').bind(rootId).first() as any
    if (!row) return c.json({ error: 'Testimonial not found' }, 404)

    const svc = await getService(db)
    await svc.softDelete(row.id)
    return c.redirect('/admin/testimonials?message=Testimonial deleted successfully')
  } catch (error) {
    console.error('Error deleting testimonial:', error)
    return c.json({ error: 'Failed to delete testimonial' }, 500)
  }
})

export default adminTestimonialsRoutes
