import { Hono } from 'hono'
import { requireAuth, requireRole } from '../middleware'
import { getCacheService, CACHE_CONFIGS } from '../services'
import type { Bindings, Variables } from '../app'
import { resolveContentVariables } from '../plugins/core-plugins/global-variables-plugin/variable-resolver'
import { dispatchHookEvent } from '../plugins/hooks/dispatch-event'
import type { HookActor } from '../plugins/hooks/catalog'

const apiContentCrudRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

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
    
    // Check for existing content with this slug in the collection
    let query = 'SELECT id FROM content WHERE collection_id = ? AND slug = ?'
    const params: string[] = [collectionId, slug]
    
    if (excludeId) {
      query += ' AND id != ?'
      params.push(excludeId)
    }
    
    const existing = await db.prepare(query).bind(...params).first()
    
    if (existing) {
      return c.json({ 
        available: false, 
        message: 'This URL slug is already in use in this collection' 
      })
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
apiContentCrudRoutes.get('/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const db = c.env.DB

    const stmt = db.prepare('SELECT * FROM content WHERE id = ?')
    const content = await stmt.bind(id).first()

    if (!content) {
      return c.json({ error: 'Content not found' }, 404)
    }

    const transformedContent = {
      id: (content as any).id,
      title: (content as any).title,
      slug: (content as any).slug,
      status: (content as any).status,
      collectionId: (content as any).collection_id,
      data: (content as any).data ? JSON.parse((content as any).data) : {},
      created_at: (content as any).created_at,
      updated_at: (content as any).updated_at
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
      { collection: (content as any).collection_id, id: (content as any).id, data: transformedContent.data },
      'fire-and-forget'
    )

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

    // Check for duplicate slug within the same collection
    const duplicateCheck = db.prepare(
      'SELECT id FROM content WHERE collection_id = ? AND slug = ?'
    )
    const existing = await duplicateCheck.bind(collectionId, finalSlug).first()

    if (existing) {
      return c.json({ error: 'A content item with this slug already exists in this collection' }, 409)
    }

    const actor: HookActor | undefined = user
      ? { id: user.userId, email: user.email ?? '', role: user.role }
      : undefined

    // Fire content:before:create (in-band) — handlers may mutate payload.data or
    // throw to cancel the write. The returned payload carries any mutations.
    let beforePayload
    try {
      beforePayload = await dispatchHookEvent(
        c,
        'content:before:create',
        { collection: collectionId, data: { title, slug: finalSlug, status: status || 'draft', ...data }, user: actor },
        'in-band'
      )
    } catch (err) {
      return c.json({ error: 'Write cancelled by plugin', details: String(err) }, 400)
    }

    // Use (possibly mutated) data from the before-hook payload.
    const finalData = typeof beforePayload?.data === 'object' ? beforePayload.data : (data || {})
    const { title: hookTitle = title, slug: hookSlug = finalSlug, status: hookStatus = status || 'draft', ...hookData } = finalData as any

    // Create new content
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
      hookSlug,
      hookTitle,
      JSON.stringify(hookData),
      hookStatus,
      user?.userId || 'system',
      now,
      now
    ).run()

    // Invalidate cache
    const cache = getCacheService(CACHE_CONFIGS.api!)
    await cache.invalidate(`content:list:${collectionId}:*`)
    await cache.invalidate('content-filtered:*')

    // Get the created content
    const getStmt = db.prepare('SELECT * FROM content WHERE id = ?')
    const createdContent = await getStmt.bind(contentId).first() as any

    // Fire content:after:create for side-effect plugins (fire-and-forget).
    dispatchHookEvent(
      c,
      'content:after:create',
      {
        collection: collectionId,
        id: contentId,
        data: createdContent?.data ? JSON.parse(createdContent.data) : {},
        user: actor,
      },
      'fire-and-forget'
    )

    return c.json({
      data: {
        id: createdContent.id,
        title: createdContent.title,
        slug: createdContent.slug,
        status: createdContent.status,
        collectionId: createdContent.collection_id,
        data: createdContent.data ? JSON.parse(createdContent.data) : {},
        created_at: createdContent.created_at,
        updated_at: createdContent.updated_at
      }
    }, 201)
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

    // Check if content exists
    const existingStmt = db.prepare('SELECT * FROM content WHERE id = ?')
    const existing = await existingStmt.bind(id).first() as any

    if (!existing) {
      return c.json({ error: 'Content not found' }, 404)
    }

    const actor: HookActor | undefined = user
      ? { id: user.userId, email: user.email ?? '', role: user.role }
      : undefined

    // Fire content:before:update (in-band) — handlers may mutate payload.data or
    // throw to cancel the write.
    let beforePayload
    try {
      beforePayload = await dispatchHookEvent(
        c,
        'content:before:update',
        {
          collection: existing.collection_id,
          id,
          data: { title: body.title, slug: body.slug, status: body.status, ...(body.data || {}) },
          user: actor,
        },
        'in-band'
      )
    } catch (err) {
      return c.json({ error: 'Write cancelled by plugin', details: String(err) }, 400)
    }

    // Apply any mutations from the before-hook.
    const mutated = beforePayload?.data as any

    // Build update fields dynamically
    const updates: string[] = []
    const params: any[] = []

    const updTitle = mutated?.title ?? body.title
    const updSlug = mutated?.slug ?? body.slug
    const updStatus = mutated?.status ?? body.status
    const updData = body.data !== undefined
      ? (mutated ? { ...body.data, ...mutated } : body.data)
      : undefined

    if (updTitle !== undefined) {
      updates.push('title = ?')
      params.push(updTitle)
    }

    if (updSlug !== undefined) {
      let finalSlug = updSlug.toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .trim()
      updates.push('slug = ?')
      params.push(finalSlug)
    }

    if (updStatus !== undefined) {
      updates.push('status = ?')
      params.push(updStatus)
    }

    if (updData !== undefined) {
      updates.push('data = ?')
      params.push(JSON.stringify(updData))
    }

    // Always update updated_at
    const now = Date.now()
    updates.push('updated_at = ?')
    params.push(now)

    // Add id to params for WHERE clause
    params.push(id)

    // Execute update
    const updateStmt = db.prepare(`
      UPDATE content SET ${updates.join(', ')}
      WHERE id = ?
    `)

    await updateStmt.bind(...params).run()

    // Invalidate cache
    const cache = getCacheService(CACHE_CONFIGS.api!)
    await cache.delete(cache.generateKey('content', id))
    await cache.invalidate(`content:list:${existing.collection_id}:*`)
    await cache.invalidate('content-filtered:*')

    // Get updated content
    const getStmt = db.prepare('SELECT * FROM content WHERE id = ?')
    const updatedContent = await getStmt.bind(id).first() as any

    const afterData = updatedContent?.data ? JSON.parse(updatedContent.data) : {}

    // Fire content:after:update (fire-and-forget).
    dispatchHookEvent(
      c,
      'content:after:update',
      { collection: existing.collection_id, id, data: afterData, user: actor },
      'fire-and-forget'
    )

    // Fire content:after:publish when status transitions to 'published'.
    if (updStatus === 'published' && existing.status !== 'published') {
      dispatchHookEvent(
        c,
        'content:after:publish',
        { collection: existing.collection_id, id, data: afterData, user: actor },
        'fire-and-forget'
      )
    }

    return c.json({
      data: {
        id: updatedContent.id,
        title: updatedContent.title,
        slug: updatedContent.slug,
        status: updatedContent.status,
        collectionId: updatedContent.collection_id,
        data: afterData,
        created_at: updatedContent.created_at,
        updated_at: updatedContent.updated_at
      }
    })
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

    // Check if content exists
    const existingStmt = db.prepare('SELECT collection_id FROM content WHERE id = ?')
    const existing = await existingStmt.bind(id).first() as any

    if (!existing) {
      return c.json({ error: 'Content not found' }, 404)
    }

    const actor: HookActor | undefined = user
      ? { id: user.userId, email: user.email ?? '', role: user.role }
      : undefined

    // Fire content:before:delete (in-band) — handlers may throw to cancel the delete.
    try {
      await dispatchHookEvent(
        c,
        'content:before:delete',
        { collection: existing.collection_id, id, data: {}, user: actor },
        'in-band'
      )
    } catch (err) {
      return c.json({ error: 'Delete cancelled by plugin', details: String(err) }, 400)
    }

    // Delete the content (hard delete for API, soft delete happens in admin routes)
    const deleteStmt = db.prepare('DELETE FROM content WHERE id = ?')
    await deleteStmt.bind(id).run()

    // Invalidate cache
    const cache = getCacheService(CACHE_CONFIGS.api!)
    await cache.delete(cache.generateKey('content', id))
    await cache.invalidate(`content:list:${existing.collection_id}:*`)
    await cache.invalidate('content-filtered:*')

    // Fire content:after:delete (fire-and-forget).
    dispatchHookEvent(
      c,
      'content:after:delete',
      { collection: existing.collection_id, id, data: {}, user: actor },
      'fire-and-forget'
    )

    return c.json({ success: true })
  } catch (error) {
    console.error('Error deleting content:', error)
    return c.json({
      error: 'Failed to delete content',
      details: error instanceof Error ? error.message : String(error)
    }, 500)
  }
})

export default apiContentCrudRoutes
