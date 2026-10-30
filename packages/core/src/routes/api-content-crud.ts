import { Hono } from 'hono'
import { requireAuth, requireRole, optionalAuth } from '../middleware'
import { canReadNonPublicContent } from './api-content-access-policy'
import { getCacheService, CACHE_CONFIGS } from '../services'
import type { Bindings, Variables } from '../app'
import { resolveContentVariables } from '../plugins/core-plugins/global-variables-plugin/variable-resolver'
import { DocumentsService, documentSecondsToMs } from '../services/documents'
import { DocumentTypeRegistry } from '../services/document-type-registry'
import { getCollectionRegistry } from '../services/collection-registry'
import { createDocumentSchema } from '../schemas/document'
import { getRequestTenant } from '../services/document-request-context'
import type { D1Database } from '@cloudflare/workers-types'
import { dispatchHookEvent } from '../plugins/hooks/dispatch-event'
import type { HookActor } from '../plugins/hooks/catalog'

const apiContentCrudRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Resolve the document type backing a content collection (by collection name OR id — for
// code-defined collections id == name). Reads the in-memory CollectionRegistry; falls back
// to a direct document_types lookup so plugin-owned types (e.g. blog_post) without a
// registered collection still resolve.
export async function resolveDocBacking(db: D1Database, collectionIdOrName: string) {
  const registry = getCollectionRegistry()
  const record = registry.getBySlugOrName(collectionIdOrName) ?? registry.getById(collectionIdOrName)
  if (record) {
    const docType = await new DocumentTypeRegistry(db).findById(record.name)
    return docType ? { coll: { id: record.id, name: record.name }, docType } : null
  }

  // No registry entry — check if document_types has a matching entry directly.
  // This handles plugin-owned types (e.g. blog_post via bootstrapDocumentTypes) that
  // exist as document types without a corresponding collection config.
  const docType = await new DocumentTypeRegistry(db).findById(collectionIdOrName)
  if (docType) {
    return { coll: { id: collectionIdOrName, name: collectionIdOrName }, docType }
  }

  return null
}

export function slugify(s?: string | null): string | null {
  if (!s) return null
  return s.toLowerCase().replace(/[^a-z0-9\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-').replace(/^-+|-+$/g, '') || null
}

// GET /api/content/check-slug - Check if slug is available in collection
// Query params: collectionId, slug, excludeId (optional - when editing)
// NOTE: This MUST come before /:id route to avoid route conflict
apiContentCrudRoutes.get('/check-slug', async (c) => {
  try {
    const db = c.env.DB
    const collectionId = c.req.query('collectionId')
    const slug = c.req.query('slug')
    const excludeId = c.req.query('excludeId') // When editing, exclude current item

    if (!collectionId || !slug) {
      return c.json({ error: 'collectionId and slug are required' }, 400)
    }

    const backing = await resolveDocBacking(db, collectionId)
    if (backing) {
      // D37: a slug is taken if ANY live revision uses it — the current draft OR a still-served
      // published row (a superseded published row keeps its slug until replaced).
      let docQuery = "SELECT root_id FROM documents WHERE type_id = ? AND tenant_id = ? AND (is_current_draft = 1 OR is_published = 1) AND deleted_at IS NULL AND slug = ?"
      const docParams: string[] = [backing.coll.name, getRequestTenant(c), slug]
      if (excludeId) { docQuery += ' AND root_id != ?'; docParams.push(excludeId) }
      const docExisting = await db.prepare(docQuery).bind(...docParams).first()
      if (docExisting) {
        return c.json({ available: false, message: 'This URL slug is already in use in this collection' })
      }
    } else {
      return c.json({ error: 'Collection not found or not document-backed' }, 400)
    }

    return c.json({ available: true })
  } catch (error: unknown) {
    console.error('Error checking slug:', error)
    return c.json({
      error: 'Failed to check slug availability',
      details: error instanceof Error ? error.message : String(error)
    }, 500)
  }
})

// GET /api/content/:id - Get single content item by ID
apiContentCrudRoutes.get('/:id', optionalAuth(), async (c) => {
  try {
    const id = c.req.param('id')
    const db = c.env.DB

    // Document-backed: /api/content returns document root ids, so resolve by root id.
    // D30: role-gate visibility — privileged callers see current-draft; anon sees published only.
    const privileged = canReadNonPublicContent(c.get('user')?.role)
    const docRow = await db
      .prepare(
        privileged
          ? "SELECT * FROM documents WHERE root_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL"
          : "SELECT * FROM documents WHERE root_id = ? AND tenant_id = ? AND is_published = 1 AND deleted_at IS NULL",
      )
      .bind(id, getRequestTenant(c))
      .first() as any

    let transformedContent: any
    if (docRow) {
      // For code-defined collections, registry id == name (== docRow.type_id).
      const coll = getCollectionRegistry().getByName(docRow.type_id)
      transformedContent = {
        id: docRow.root_id,
        title: docRow.title,
        slug: docRow.slug,
        status: docRow.status,
        collectionId: coll?.id ?? docRow.type_id,
        data: docRow.data ? JSON.parse(docRow.data) : {},
        // D29: document timestamps are SECONDS; legacy `content` API contract is MILLISECONDS.
        created_at: documentSecondsToMs(docRow.created_at),
        updated_at: documentSecondsToMs(docRow.updated_at),
      }
    } else {
      return c.json({ error: 'Content not found' }, 404)
    }

    // Resolve {variable_key} tokens in content data
    const resolveVars = c.req.query('resolve_variables') !== 'false'
    if (resolveVars) {
      transformedContent.data = await resolveContentVariables(transformedContent.data, db)
    }

    // Fire content:read for observability plugins (fire-and-forget).
    dispatchHookEvent(
      c,
      'content:read',
      { collection: docRow.type_id, id: docRow.root_id, data: transformedContent.data },
      'fire-and-forget'
    )

    // ?fields= projection: e.g. ?fields=id,title,data.excerpt
    const fieldsParam = c.req.query('fields')
    if (fieldsParam) {
      const projFields = fieldsParam.split(',').map(s => s.trim()).filter(Boolean)
      if (projFields.length > 0) {
        const result: any = {}
        const dataSubFields: string[] = []
        for (const f of projFields) {
          if (f === 'data') {
            result.data = transformedContent.data
          } else if (f.startsWith('data.')) {
            dataSubFields.push(f.slice(5))
          } else if (Object.prototype.hasOwnProperty.call(transformedContent, f)) {
            result[f] = transformedContent[f]
          }
        }
        if (dataSubFields.length > 0 && !result.data) {
          result.data = {}
          for (const sub of dataSubFields) {
            if (transformedContent.data && Object.prototype.hasOwnProperty.call(transformedContent.data, sub)) {
              result.data[sub] = transformedContent.data[sub]
            }
          }
        }
        return c.json({ data: result })
      }
    }

    return c.json({ data: transformedContent })
  } catch (error) {
    console.error('Error fetching content:', error)
    return c.json({
      error: 'Failed to fetch content',
      details: error instanceof Error ? error.message : String(error)
    }, 500)
  }
})

// POST /api/content - Create new content (requires authentication)
apiContentCrudRoutes.post('/', requireAuth(), requireRole(['admin', 'editor', 'author']), async (c) => {
  try {
    const db = c.env.DB
    const user = c.get('user')
    const body = await c.req.json()

    const { collectionId, title, slug, status, data } = body

    // Validate required fields
    if (!collectionId) {
      return c.json({ error: 'collectionId is required' }, 400)
    }

    if (!title) {
      return c.json({ error: 'title is required' }, 400)
    }

    // Generate slug from title if not provided
    let finalSlug = slug || title
    finalSlug = finalSlug.toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .trim()

    // Document-backed collection → create a document (legacy content decommission).
    const backing = await resolveDocBacking(db, collectionId)
    if (backing) {
      const dup = await db
        // D37: reject if the slug is used by any live revision (current draft OR served published row).
        .prepare("SELECT root_id FROM documents WHERE type_id = ? AND tenant_id = ? AND (is_current_draft = 1 OR is_published = 1) AND deleted_at IS NULL AND slug = ?")
        .bind(backing.coll.name, getRequestTenant(c), finalSlug)
        .first()
      if (dup) {
        return c.json({ error: 'A content item with this slug already exists in this collection' }, 409)
      }

      const actor: HookActor | undefined = user
        ? { id: user.userId, email: user.email ?? '', role: user.role }
        : undefined

      // Fire content:before:create (in-band) — handlers may mutate payload.data or throw to cancel.
      let hookData = data || {}
      try {
        const beforePayload = await dispatchHookEvent(
          c,
          'content:before:create',
          { collection: backing.coll.name, data: { title, slug: finalSlug, status: status || 'draft', ...hookData }, user: actor },
          'in-band'
        )
        hookData = typeof beforePayload?.data === 'object' ? beforePayload.data : hookData
      } catch (err) {
        return c.json({ error: 'Write cancelled by plugin', details: String(err) }, 400)
      }

      const tenantId = getRequestTenant(c)
      const svc = new DocumentsService(db, {
        queryableFields: backing.docType.queryableFields ?? [],
        typeSchemaVersion: backing.docType.schemaVersion ?? 1,
        maxVersionsPerRoot: backing.docType.settings?.maxVersionsPerRoot ?? 50,
        tenantId,
        versioning: backing.docType.settings?.versioning ?? false,
      })
      const doc = await svc.create(
        createDocumentSchema.parse({
          typeId: backing.coll.name, tenantId, locale: 'default',
          title, slug: finalSlug, data: hookData, publishOnCreate: (status || 'draft') === 'published',
        }),
        user?.userId,
      )
      const cache = getCacheService(CACHE_CONFIGS.api!)
      await cache.invalidate('api:content-filtered:*')
      await cache.invalidate(`api:collection-content-filtered:${backing.coll.name}:*`)

      // Fire content:after:create for side-effect plugins (fire-and-forget).
      dispatchHookEvent(
        c,
        'content:after:create',
        { collection: backing.coll.name, id: doc.rootId, data: doc.data ?? {}, user: actor },
        'fire-and-forget'
      )

      return c.json({
        data: { id: doc.rootId, title: doc.title, slug: doc.slug, status: doc.status, collectionId: backing.coll.id, data: doc.data, created_at: documentSecondsToMs(doc.createdAt), updated_at: documentSecondsToMs(doc.updatedAt) },
      }, 201)
    }

    return c.json({ error: 'Collection is not document-backed' }, 400)
  } catch (error) {
    console.error('Error creating content:', error)
    return c.json({
      error: 'Failed to create content',
      details: error instanceof Error ? error.message : String(error)
    }, 500)
  }
})

// PUT /api/content/:id - Update content (requires authentication)
apiContentCrudRoutes.put('/:id', requireAuth(), requireRole(['admin', 'editor', 'author']), async (c) => {
  try {
    const id = c.req.param('id')
    const db = c.env.DB
    const user = c.get('user')
    const body = await c.req.json()

    // Document-backed: :id is a document root id → save a new draft and sync publish state. D39: skip
    // soft-deleted roots (so PUT can't resurrect one) → falls through → 404.
    const tenantId = getRequestTenant(c)
    const docRow = await db
      .prepare("SELECT root_id, type_id FROM documents WHERE root_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL")
      .bind(id, tenantId)
      .first() as any
    if (docRow) {
      const actor: HookActor | undefined = user
        ? { id: user.userId, email: user.email ?? '', role: user.role }
        : undefined

      // Fire content:before:update (in-band) — handlers may mutate payload.data or throw to cancel.
      let hookData = body.data
      try {
        const beforePayload = await dispatchHookEvent(
          c,
          'content:before:update',
          { collection: docRow.type_id, id, data: { title: body.title, slug: body.slug, status: body.status, ...(body.data || {}) }, user: actor },
          'in-band'
        )
        if (typeof beforePayload?.data === 'object') hookData = beforePayload.data
      } catch (err) {
        return c.json({ error: 'Write cancelled by plugin', details: String(err) }, 400)
      }

      const docType = await new DocumentTypeRegistry(db).findById(docRow.type_id)
      const svc = new DocumentsService(db, {
        queryableFields: docType?.queryableFields ?? [],
        typeSchemaVersion: docType?.schemaVersion ?? 1,
        maxVersionsPerRoot: docType?.settings?.maxVersionsPerRoot ?? 50,
        tenantId,
        versioning: docType?.settings?.versioning ?? false,
      })
      const input: any = {}
      if (body.title !== undefined) input.title = body.title
      if (body.slug !== undefined) input.slug = slugify(body.slug)
      if (hookData !== undefined) input.data = hookData
      const newDraft = await svc.saveDraft(id!, input, user?.userId)
      const pub = await db.prepare("SELECT id FROM documents WHERE root_id = ? AND is_published = 1 AND tenant_id = ?").bind(id, tenantId).first() as any
      // D38: an explicit status wins; with NO status, preserve the prior effective state.
      const wasPublished = !!pub
      if (body.status === 'published' || (body.status === undefined && pub)) {
        await svc.publish(newDraft.id, user?.userId)
      } else if (body.status === 'draft' && pub) {
        await svc.unpublish(pub.id)
      }
      const cache = getCacheService(CACHE_CONFIGS.api!)
      await cache.invalidate('api:content-filtered:*')
      await cache.invalidate(`api:collection-content-filtered:${docRow.type_id}:*`)
      const coll = getCollectionRegistry().getByName(docRow.type_id)
      const saved = await db.prepare('SELECT * FROM documents WHERE id = ?').bind(newDraft.id).first() as any
      const savedData = saved?.data ? JSON.parse(saved.data) : {}

      // Fire content:after:update (fire-and-forget).
      dispatchHookEvent(c, 'content:after:update', { collection: docRow.type_id, id, data: savedData, user: actor }, 'fire-and-forget')

      // Fire content:after:publish when status transitions to published.
      const nowPublished = body.status === 'published' || (body.status === undefined && wasPublished)
      if (nowPublished && !wasPublished) {
        dispatchHookEvent(c, 'content:after:publish', { collection: docRow.type_id, id, data: savedData, user: actor }, 'fire-and-forget')
      }

      return c.json({
        data: { id: saved.root_id, title: saved.title, slug: saved.slug, status: saved.status, collectionId: coll?.id ?? docRow.type_id, data: savedData, created_at: documentSecondsToMs(saved.created_at), updated_at: documentSecondsToMs(saved.updated_at) },
      })
    }

    return c.json({ error: 'Content not found' }, 404)
  } catch (error) {
    console.error('Error updating content:', error)
    return c.json({
      error: 'Failed to update content',
      details: error instanceof Error ? error.message : String(error)
    }, 500)
  }
})

// DELETE /api/content/:id - Delete content (requires authentication)
apiContentCrudRoutes.delete('/:id', requireAuth(), requireRole(['admin', 'editor', 'author']), async (c) => {
  try {
    const id = c.req.param('id')
    const db = c.env.DB
    const user = c.get('user')

    // Document-backed: :id is a document root id → soft-delete every version row of the root. D39:
    // ignore an already soft-deleted root so a second DELETE falls through → 404.
    const tenantId = getRequestTenant(c)
    const docRow = await db.prepare("SELECT type_id FROM documents WHERE root_id = ? AND tenant_id = ? AND deleted_at IS NULL LIMIT 1").bind(id, tenantId).first() as any
    if (docRow) {
      const actor: HookActor | undefined = user
        ? { id: user.userId, email: user.email ?? '', role: user.role }
        : undefined

      // Fire content:before:delete (in-band) — handlers may throw to cancel.
      try {
        await dispatchHookEvent(c, 'content:before:delete', { collection: docRow.type_id, id, data: {}, user: actor }, 'in-band')
      } catch (err) {
        return c.json({ error: 'Delete cancelled by plugin', details: String(err) }, 400)
      }

      const now = Math.floor(Date.now() / 1000)
      await db.prepare("UPDATE documents SET deleted_at = ?, updated_at = ? WHERE root_id = ? AND tenant_id = ?").bind(now, now, id, tenantId).run()
      const cache = getCacheService(CACHE_CONFIGS.api!)
      await cache.invalidate('api:content-filtered:*')
      await cache.invalidate(`api:collection-content-filtered:${docRow.type_id}:*`)

      // Fire content:after:delete (fire-and-forget).
      dispatchHookEvent(c, 'content:after:delete', { collection: docRow.type_id, id, data: {}, user: actor }, 'fire-and-forget')

      return c.json({ success: true })
    }

    return c.json({ error: 'Content not found' }, 404)
  } catch (error) {
    console.error('Error deleting content:', error)
    return c.json({
      error: 'Failed to delete content',
      details: error instanceof Error ? error.message : String(error)
    }, 500)
  }
})

export default apiContentCrudRoutes
