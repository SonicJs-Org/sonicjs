/**
 * Testimonials plugin — data layer migrated to document model (migration 037).
 * The `testimonials` table was dropped in migration 038.
 * Public API keeps the same JSON response shape for backward compatibility;
 * `id` is now the document rootId (string) instead of an autoincrement integer.
 */
import { Hono } from 'hono'
import { z } from 'zod'
import type { Plugin } from '../../types'
import { PluginBuilder } from '../../sdk/plugin-builder'
import { DocumentsService } from '../../../services/documents'
import { DocumentTypeRegistry } from '../../../services/document-type-registry'

const testimonialSchema = z.object({
  authorName: z.string().min(1, 'Author name is required').max(100),
  authorTitle: z.string().max(100).optional(),
  authorCompany: z.string().max(100).optional(),
  testimonialText: z.string().min(1, 'Testimonial text is required').max(1000),
  rating: z.number().min(1).max(5).optional(),
  isPublished: z.boolean().default(false), // new testimonials default to DRAFT, not auto-published
  sortOrder: z.number().default(0),
})

async function getService(db: D1Database) {
  const registry = new DocumentTypeRegistry(db)
  const docType = await registry.findById('testimonial')
  return new DocumentsService(db, {
    queryableFields: docType?.queryableFields ?? [],
    typeSchemaVersion: docType?.schemaVersion ?? 1,
    maxVersionsPerRoot: docType?.settings.maxVersionsPerRoot ?? 50,
  })
}

// Map a document row to the legacy API shape (backward-compatible).
function docToApiShape(row: any) {
  const data = typeof row.data === 'string' ? JSON.parse(row.data) : (row.data ?? {})
  return {
    id: row.root_id ?? row.rootId,
    author_name: data.authorName ?? '',
    author_title: data.authorTitle ?? null,
    author_company: data.authorCompany ?? null,
    testimonial_text: data.testimonialText ?? '',
    rating: data.rating ?? null,
    isPublished: row.is_published === 1 || row.isPublished === true ? 1 : 0,
    sortOrder: data.sortOrder ?? 0,
    created_at: row.created_at ?? row.createdAt,
    updated_at: row.updated_at ?? row.updatedAt,
  }
}

const testimonialAPIRoutes = new Hono()

// ─── List published testimonials ──────────────────────────────────────────────
testimonialAPIRoutes.get('/', async (c) => {
  try {
    const db = (c as any).env?.DB as D1Database
    const { published, minRating } = c.req.query()
    const now = Math.floor(Date.now() / 1000)

    const params: (string | number)[] = ['default', 'testimonial', now, now]
    let sql = `SELECT * FROM documents
               WHERE tenant_id = ? AND type_id = ? AND is_published = 1 AND deleted_at IS NULL
                 AND (scheduled_at IS NULL OR scheduled_at <= ?)
                 AND (expires_at IS NULL OR expires_at > ?)`

    if (published === 'false') {
      // Caller explicitly wants drafts — return current drafts instead
      sql = `SELECT * FROM documents
             WHERE tenant_id = ? AND type_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
               AND (scheduled_at IS NULL OR scheduled_at <= ?)
               AND (expires_at IS NULL OR expires_at > ?)`
    }

    if (minRating) {
      sql += ' AND q_tst_rating >= ?'
      params.push(parseInt(minRating, 10))
    }

    sql += ' ORDER BY q_tst_sort_order ASC, updated_at DESC'

    const { results } = await db.prepare(sql).bind(...params).all()
    return c.json({ success: true, data: (results ?? []).map(docToApiShape) })
  } catch (error) {
    console.error('Error fetching testimonials:', error)
    return c.json({ success: false, error: 'Failed to fetch testimonials' }, 500)
  }
})

// ─── Get single testimonial ───────────────────────────────────────────────────
testimonialAPIRoutes.get('/:id', async (c) => {
  try {
    const db = (c as any).env?.DB as D1Database
    const rootId = c.req.param('id')
    const now = Math.floor(Date.now() / 1000)

    const row = await db.prepare(
      `SELECT * FROM documents
       WHERE root_id = ? AND tenant_id = ? AND is_published = 1 AND deleted_at IS NULL
         AND (scheduled_at IS NULL OR scheduled_at <= ?)
         AND (expires_at IS NULL OR expires_at > ?)`
    ).bind(rootId, 'default', now, now).first()

    if (!row) return c.json({ error: 'Testimonial not found' }, 404)
    return c.json({ success: true, data: docToApiShape(row) })
  } catch (error) {
    return c.json({ success: false, error: 'Failed to fetch testimonial' }, 500)
  }
})

// ─── Create ───────────────────────────────────────────────────────────────────
testimonialAPIRoutes.post('/', async (c) => {
  try {
    const db = (c as any).env?.DB as D1Database
    const body = await c.req.json()
    const validated = testimonialSchema.parse(body)
    const svc = await getService(db)

    const doc = await svc.create({
      typeId: 'testimonial', tenantId: 'default', locale: 'default',
      title: validated.authorName, sortOrder: validated.sortOrder,
      data: {
        authorName: validated.authorName, authorTitle: validated.authorTitle,
        authorCompany: validated.authorCompany, testimonialText: validated.testimonialText,
        rating: validated.rating, sortOrder: validated.sortOrder,
      },
      parentRootId: '', visible: true, metadata: {}, publishOnCreate: false,
    })

    if (validated.isPublished) await svc.publish(doc.id)

    // Fetch the saved row for the response shape.
    const saved = await db.prepare('SELECT * FROM documents WHERE id = ?').bind(doc.id).first()
    return c.json({ success: true, data: docToApiShape(saved), message: 'Testimonial created successfully' }, 201)
  } catch (error) {
    if (error instanceof z.ZodError) return c.json({ success: false, error: 'Validation failed', details: error.issues }, 400)
    console.error('Error creating testimonial:', error)
    return c.json({ success: false, error: 'Failed to create testimonial' }, 500)
  }
})

// ─── Update (save new draft + sync publish state) ─────────────────────────────
testimonialAPIRoutes.put('/:id', async (c) => {
  try {
    const db = (c as any).env?.DB as D1Database
    const rootId = c.req.param('id')
    const body = await c.req.json()
    const validated = testimonialSchema.partial().parse(body)
    const svc = await getService(db)

    const data: Record<string, unknown> = {}
    if (validated.authorName !== undefined) data.authorName = validated.authorName
    if (validated.authorTitle !== undefined) data.authorTitle = validated.authorTitle
    if (validated.authorCompany !== undefined) data.authorCompany = validated.authorCompany
    if (validated.testimonialText !== undefined) data.testimonialText = validated.testimonialText
    if (validated.rating !== undefined) data.rating = validated.rating
    if (validated.sortOrder !== undefined) data.sortOrder = validated.sortOrder

    if (Object.keys(data).length === 0 && validated.isPublished === undefined) {
      return c.json({ error: 'No fields to update' }, 400)
    }

    const newDraft = await svc.saveDraft(rootId, {
      title: validated.authorName, sortOrder: validated.sortOrder, data,
    })

    // saveDraft always returns an unpublished draft, so sync against the root's published row
    // (gating on newDraft.isPublished would make unpublish dead code).
    if (validated.isPublished !== undefined) {
      const pubRow = await db
        .prepare('SELECT id FROM documents WHERE root_id = ? AND is_published = 1 AND tenant_id = ?')
        .bind(rootId, 'default')
        .first() as { id: string } | null
      if (validated.isPublished) await svc.publish(newDraft.id)
      else if (pubRow) await svc.unpublish(pubRow.id)
    }

    const saved = await db.prepare('SELECT * FROM documents WHERE id = ?').bind(newDraft.id).first()
    return c.json({ success: true, data: docToApiShape(saved), message: 'Testimonial updated successfully' })
  } catch (error) {
    if (error instanceof z.ZodError) return c.json({ success: false, error: 'Validation failed', details: error.issues }, 400)
    console.error('Error updating testimonial:', error)
    return c.json({ success: false, error: 'Failed to update testimonial' }, 500)
  }
})

// ─── Delete (soft delete) ─────────────────────────────────────────────────────
testimonialAPIRoutes.delete('/:id', async (c) => {
  try {
    const db = (c as any).env?.DB as D1Database
    const rootId = c.req.param('id')
    const row = await db.prepare('SELECT id FROM documents WHERE root_id = ? AND is_current_draft = 1').bind(rootId).first() as any
    if (!row) return c.json({ error: 'Testimonial not found' }, 404)

    const svc = await getService(db)
    await svc.softDelete(row.id)
    return c.json({ success: true, message: 'Testimonial deleted successfully' })
  } catch (error) {
    return c.json({ success: false, error: 'Failed to delete testimonial' }, 500)
  }
})

export function createTestimonialPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: 'testimonials-plugin',
    version: '1.0.0-beta.2',
    description: 'Customer testimonials management — backed by the document model'
  })

  builder.metadata({ author: { name: 'SonicJS', email: 'info@sonicjs.com' }, license: 'MIT', compatibility: '^1.0.0' })

  // No addModel() — the testimonials table no longer exists.
  // Data lives in the documents table (type_id = 'testimonial').

  builder.addRoute('/api/testimonials', testimonialAPIRoutes, {
    description: 'Testimonials API — document-model backed',
    requiresAuth: false
  })

  builder.addAdminPage('/testimonials', 'Testimonials', 'TestimonialsListView', {
    description: 'Manage customer testimonials', icon: 'star', permissions: ['admin', 'editor']
  })
  builder.addAdminPage('/testimonials/new', 'New Testimonial', 'TestimonialsFormView', { permissions: ['admin', 'editor'] })
  builder.addAdminPage('/testimonials/:id', 'Edit Testimonial', 'TestimonialsFormView', { permissions: ['admin', 'editor'] })
  builder.addMenuItem('Testimonials', '/admin/testimonials', { icon: 'star', order: 60, permissions: ['admin', 'editor'] })

  builder.lifecycle({
    install: async () => { console.log('Testimonials plugin installed (document-model backed)') },
    uninstall: async () => { console.log('Testimonials plugin uninstalled') },
    activate: async () => { console.log('Testimonials plugin activated') },
    deactivate: async () => { console.log('Testimonials plugin deactivated') },
  })

  return builder.build() as Plugin
}

export const testimonialsPlugin = createTestimonialPlugin()
