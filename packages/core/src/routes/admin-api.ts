/**
 * Admin API Routes
 *
 * Provides JSON API endpoints for admin operations
 * These routes complement the admin UI and can be used programmatically
 */

import { Hono } from 'hono'
import { z } from 'zod'
// import { zValidator } from '@hono/zod-validator'
import { requireAuth, requireRole } from '../middleware'
import type { Bindings, Variables } from '../app'

export const adminApiRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply auth middleware to all admin routes
adminApiRoutes.use('*', requireAuth())
adminApiRoutes.use('*', requireRole(['admin', 'editor']))

/**
 * Get dashboard statistics
 * GET /admin/api/stats
 */
adminApiRoutes.get('/stats', async (c) => {
  try {
    const db = c.env.DB

    // Get collections count
    let collectionsCount = 0
    try {
      const collectionsStmt = db.prepare("SELECT COUNT(*) as count FROM collections WHERE is_active = 1 AND (source_type IS NULL OR source_type = 'user')")
      const collectionsResult = await collectionsStmt.first()
      collectionsCount = (collectionsResult as any)?.count || 0
    } catch (error) {
      console.error('Error fetching collections count:', error)
    }

    // Get content count
    let contentCount = 0
    try {
      const contentStmt = db.prepare("SELECT COUNT(*) as count FROM content c JOIN collections col ON c.collection_id = col.id WHERE c.deleted_at IS NULL AND (col.source_type IS NULL OR col.source_type = 'user')")
      const contentResult = await contentStmt.first()
      contentCount = (contentResult as any)?.count || 0
    } catch (error) {
      console.error('Error fetching content count:', error)
    }

    // Get media count and total size
    let mediaCount = 0
    let mediaSize = 0
    try {
      const mediaStmt = db.prepare('SELECT COUNT(*) as count, COALESCE(SUM(size), 0) as total_size FROM media WHERE deleted_at IS NULL')
      const mediaResult = await mediaStmt.first()
      mediaCount = (mediaResult as any)?.count || 0
      mediaSize = (mediaResult as any)?.total_size || 0
    } catch (error) {
      console.error('Error fetching media count:', error)
    }

    // Get users count
    let usersCount = 0
    try {
      const usersStmt = db.prepare('SELECT COUNT(*) as count FROM users WHERE is_active = 1')
      const usersResult = await usersStmt.first()
      usersCount = (usersResult as any)?.count || 0
    } catch (error) {
      console.error('Error fetching users count:', error)
    }

    return c.json({
      collections: collectionsCount,
      contentItems: contentCount,
      mediaFiles: mediaCount,
      mediaSize: mediaSize,
      users: usersCount,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Error fetching stats:', error)
    return c.json({ error: 'Failed to fetch statistics' }, 500)
  }
})

/**
 * Get storage usage
 * GET /admin/api/storage
 */
adminApiRoutes.get('/storage', async (c) => {
  try {
    const db = c.env.DB

    // Get database size from D1 metadata
    let databaseSize = 0
    try {
      const result = await db.prepare('SELECT 1').run()
      databaseSize = (result as any)?.meta?.size_after || 0
    } catch (error) {
      console.error('Error fetching database size:', error)
    }

    // Get media total size
    let mediaSize = 0
    try {
      const mediaStmt = db.prepare('SELECT COALESCE(SUM(size), 0) as total_size FROM media WHERE deleted_at IS NULL')
      const mediaResult = await mediaStmt.first()
      mediaSize = (mediaResult as any)?.total_size || 0
    } catch (error) {
      console.error('Error fetching media size:', error)
    }

    return c.json({
      databaseSize,
      mediaSize,
      totalSize: databaseSize + mediaSize,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Error fetching storage usage:', error)
    return c.json({ error: 'Failed to fetch storage usage' }, 500)
  }
})

/**
 * Get recent activity
 * GET /admin/api/activity
 */
adminApiRoutes.get('/activity', async (c) => {
  try {
    const db = c.env.DB
    const limit = parseInt(c.req.query('limit') || '10')

    // Get recent activities from activity_logs table
    const activityStmt = db.prepare(`
      SELECT
        a.id,
        a.action,
        a.resource_type,
        a.resource_id,
        a.details,
        a.created_at,
        u.email,
        u.first_name,
        u.last_name
      FROM activity_logs a
      LEFT JOIN users u ON a.user_id = u.id
      WHERE a.resource_type IN ('content', 'collections', 'users', 'media')
      ORDER BY a.created_at DESC
      LIMIT ?
    `)

    const { results } = await activityStmt.bind(limit).all()

    const recentActivity = (results || []).map((row: any) => {
      const userName = row.first_name && row.last_name
        ? `${row.first_name} ${row.last_name}`
        : row.email || 'System'

      let details: any = {}
      try {
        details = row.details ? JSON.parse(row.details) : {}
      } catch (e) {
        console.error('Error parsing activity details:', e)
      }

      return {
        id: row.id,
        type: row.resource_type,
        action: row.action,
        resource_id: row.resource_id,
        details,
        timestamp: new Date(Number(row.created_at)).toISOString(),
        user: userName
      }
    })

    return c.json({
      data: recentActivity,
      count: recentActivity.length,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Error fetching recent activity:', error)
    return c.json({ error: 'Failed to fetch recent activity' }, 500)
  }
})

/**
 * Collection management schema
 */
const createCollectionSchema = z.object({
  name: z.string().min(1).max(255).regex(/^[a-z0-9_]+$/, 'Must contain only lowercase letters, numbers, and underscores'),
  displayName: z.string().min(1).max(255).optional(),
  display_name: z.string().min(1).max(255).optional(),
  description: z.string().optional()
}).refine(data => data.displayName || data.display_name, {
  message: 'Either displayName or display_name is required',
  path: ['displayName']
})

const updateCollectionSchema = z.object({
  display_name: z.string().min(1).max(255).optional(),
  description: z.string().optional(),
  is_active: z.boolean().optional()
})

/**
 * Get all collections
 * GET /admin/api/collections
 */
adminApiRoutes.get('/collections', async (c) => {
  try {
    const db = c.env.DB
    const search = c.req.query('search') || ''
    const includeInactive = c.req.query('includeInactive') === 'true'

    let stmt
    let results

    if (search) {
      stmt = db.prepare(`
        SELECT id, name, display_name, description, created_at, updated_at, is_active, managed
        FROM collections
        WHERE ${includeInactive ? '1=1' : 'is_active = 1'}
        AND (source_type IS NULL OR source_type = 'user')
        AND (name LIKE ? OR display_name LIKE ? OR description LIKE ?)
        ORDER BY created_at DESC
      `)
      const searchParam = `%${search}%`
      const queryResults = await stmt.bind(searchParam, searchParam, searchParam).all()
      results = queryResults.results
    } else {
      stmt = db.prepare(`
        SELECT id, name, display_name, description, created_at, updated_at, is_active, managed
        FROM collections
        WHERE (source_type IS NULL OR source_type = 'user')
        ${includeInactive ? '' : 'AND is_active = 1'}
        ORDER BY created_at DESC
      `)
      const queryResults = await stmt.all()
      results = queryResults.results
    }

    // Get field counts
    const fieldCountStmt = db.prepare('SELECT collection_id, COUNT(*) as count FROM content_fields GROUP BY collection_id')
    const { results: fieldCountResults } = await fieldCountStmt.all()
    const fieldCounts = new Map((fieldCountResults || []).map((row: any) => [String(row.collection_id), Number(row.count)]))

    const collections = (results || []).map((row: any) => ({
      id: row.id,
      name: row.name,
      display_name: row.display_name,
      description: row.description,
      created_at: Number(row.created_at),
      updated_at: Number(row.updated_at),
      is_active: row.is_active === 1,
      managed: row.managed === 1,
      field_count: fieldCounts.get(String(row.id)) || 0
    }))

    return c.json({
      data: collections,
      count: collections.length,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Error fetching collections:', error)
    return c.json({ error: 'Failed to fetch collections' }, 500)
  }
})

/**
 * Get single collection
 * GET /admin/api/collections/:id
 */
adminApiRoutes.get('/collections/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const db = c.env.DB

    const stmt = db.prepare('SELECT * FROM collections WHERE id = ?')
    const collection = await stmt.bind(id).first() as any

    if (!collection) {
      return c.json({ error: 'Collection not found' }, 404)
    }

    // Get collection fields
    const fieldsStmt = db.prepare(`
      SELECT * FROM content_fields
      WHERE collection_id = ?
      ORDER BY field_order ASC
    `)
    const { results: fieldsResults } = await fieldsStmt.bind(id).all()

    const fields = (fieldsResults || []).map((row: any) => ({
      id: row.id,
      field_name: row.field_name,
      field_type: row.field_type,
      field_label: row.field_label,
      field_options: row.field_options ? JSON.parse(row.field_options) : {},
      field_order: row.field_order,
      is_required: row.is_required === 1,
      is_searchable: row.is_searchable === 1,
      created_at: Number(row.created_at),
      updated_at: Number(row.updated_at)
    }))

    return c.json({
      id: collection.id,
      name: collection.name,
      display_name: collection.display_name,
      description: collection.description,
      is_active: collection.is_active === 1,
      managed: collection.managed === 1,
      schema: collection.schema ? JSON.parse(collection.schema) : null,
      created_at: Number(collection.created_at),
      updated_at: Number(collection.updated_at),
      fields
    })
  } catch (error) {
    console.error('Error fetching collection:', error)
    return c.json({ error: 'Failed to fetch collection' }, 500)
  }
})

/**
 * Get reference options for a collection
 * GET /admin/api/references?collection=<nameOrId>&search=<query>&limit=20&id=<contentId>
 */
adminApiRoutes.get('/references', async (c) => {
  try {
    const db = c.env.DB
    const url = new URL(c.req.url)
    const collectionParams = url.searchParams
      .getAll('collection')
      .flatMap((value) => value.split(','))
      .map((value) => value.trim())
      .filter(Boolean)
    const search = c.req.query('search') || ''
    const id = c.req.query('id') || ''
    const limit = Math.min(Number.parseInt(c.req.query('limit') || '20', 10) || 20, 100)

    if (collectionParams.length === 0) {
      return c.json({ error: 'Collection is required' }, 400)
    }

    const placeholders = collectionParams.map(() => '?').join(', ')
    const collectionStmt = db.prepare(`
      SELECT id, name, display_name
      FROM collections
      WHERE id IN (${placeholders}) OR name IN (${placeholders})
    `)
    const collectionResults = await collectionStmt
      .bind(...collectionParams, ...collectionParams)
      .all()
    const collections = (collectionResults.results || []) as any[]

    if (collections.length === 0) {
      return c.json({ error: 'Collection not found' }, 404)
    }

    const collectionById = Object.fromEntries(
      collections.map((entry) => [
        entry.id,
        {
          id: entry.id,
          name: entry.name,
          display_name: entry.display_name
        }
      ])
    )
    const collectionIds = collections.map((entry) => entry.id)

    if (id) {
      const idPlaceholders = collectionIds.map(() => '?').join(', ')
      const itemStmt = db.prepare(`
        SELECT id, title, slug, collection_id
        FROM content
        WHERE id = ? AND collection_id IN (${idPlaceholders})
        LIMIT 1
      `)
      const item = await itemStmt.bind(id, ...collectionIds).first() as any

      if (!item) {
        return c.json({ error: 'Reference not found' }, 404)
      }

      return c.json({
        data: {
          id: item.id,
          title: item.title,
          slug: item.slug,
          collection: collectionById[item.collection_id]
        }
      })
    }

    let stmt
    let results

    const listPlaceholders = collectionIds.map(() => '?').join(', ')
    const statusFilterValues = ['published']
    const statusClause = ` AND status IN (${statusFilterValues.map(() => '?').join(', ')})`

    if (search) {
      const searchParam = `%${search}%`
      stmt = db.prepare(`
        SELECT id, title, slug, status, updated_at, collection_id
        FROM content
        WHERE collection_id IN (${listPlaceholders})
        AND (title LIKE ? OR slug LIKE ?)
        ${statusClause}
        ORDER BY updated_at DESC
        LIMIT ?
      `)
      const queryResults = await stmt
        .bind(...collectionIds, searchParam, searchParam, ...statusFilterValues, limit)
        .all()
      results = queryResults.results
    } else {
      stmt = db.prepare(`
        SELECT id, title, slug, status, updated_at, collection_id
        FROM content
        WHERE collection_id IN (${listPlaceholders})
        ${statusClause}
        ORDER BY updated_at DESC
        LIMIT ?
      `)
      const queryResults = await stmt
        .bind(...collectionIds, ...statusFilterValues, limit)
        .all()
      results = queryResults.results
    }

    const items = (results || []).map((row: any) => ({
      id: row.id,
      title: row.title,
      slug: row.slug,
      status: row.status,
      updated_at: row.updated_at ? Number(row.updated_at) : null,
      collection: collectionById[row.collection_id]
    }))

    return c.json({
      data: items,
      count: items.length
    })
  } catch (error) {
    console.error('Error fetching reference options:', error)
    return c.json({ error: 'Failed to fetch references' }, 500)
  }
})

/**
 * Create collection
 * POST /admin/api/collections
 */
adminApiRoutes.post('/collections', async (c) => {
    try {
      // Validate content type
      const contentType = c.req.header('Content-Type')
      if (!contentType || !contentType.includes('application/json')) {
        return c.json({ error: 'Content-Type must be application/json' }, 400)
      }

      let body
      try {
        body = await c.req.json()
      } catch (e) {
        return c.json({ error: 'Invalid JSON in request body' }, 400)
      }

      const validation = createCollectionSchema.safeParse(body)
      if (!validation.success) {
        return c.json({ error: 'Validation failed', details: validation.error.issues }, 400)
      }
      const validatedData = validation.data
      const db = c.env.DB
      const _user = c.get('user')

      // Handle both camelCase and snake_case for display_name
      const displayName = validatedData.displayName || validatedData.display_name || ''

      // Check if collection already exists
      const existingStmt = db.prepare('SELECT id FROM collections WHERE name = ?')
      const existing = await existingStmt.bind(validatedData.name).first()

      if (existing) {
        return c.json({ error: 'A collection with this name already exists' }, 400)
      }

      // Create basic schema
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

      const collectionId = crypto.randomUUID()
      const now = Date.now()

      const insertStmt = db.prepare(`
        INSERT INTO collections (id, name, display_name, description, schema, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `)

      await insertStmt.bind(
        collectionId,
        validatedData.name,
        displayName,
        validatedData.description || null,
        JSON.stringify(basicSchema),
        1, // is_active
        now,
        now
      ).run()

      // Clear cache
      try {
        await c.env.CACHE_KV.delete('cache:collections:all')
        await c.env.CACHE_KV.delete(`cache:collection:${validatedData.name}`)
      } catch (e) {
        console.error('Error clearing cache:', e)
      }

      return c.json({
        id: collectionId,
        name: validatedData.name,
        displayName: displayName,
        description: validatedData.description,
        created_at: now
      }, 201)
    } catch (error) {
      console.error('Error creating collection:', error)
      return c.json({ error: 'Failed to create collection' }, 500)
    }
})

/**
 * Update collection
 * PATCH /admin/api/collections/:id
 */
adminApiRoutes.patch('/collections/:id', async (c) => {
    try {
      const id = c.req.param('id')
      const body = await c.req.json()
      const validation = updateCollectionSchema.safeParse(body)
      if (!validation.success) {
        return c.json({ error: 'Validation failed', details: validation.error.issues }, 400)
      }
      const validatedData = validation.data
      const db = c.env.DB

      // Check if collection exists
      const checkStmt = db.prepare('SELECT * FROM collections WHERE id = ?')
      const existing = await checkStmt.bind(id).first() as any

      if (!existing) {
        return c.json({ error: 'Collection not found' }, 404)
      }

      // Build update query
      const updateFields: string[] = []
      const updateParams: any[] = []

      if (validatedData.display_name !== undefined) {
        updateFields.push('display_name = ?')
        updateParams.push(validatedData.display_name)
      }

      if (validatedData.description !== undefined) {
        updateFields.push('description = ?')
        updateParams.push(validatedData.description)
      }

      if (validatedData.is_active !== undefined) {
        updateFields.push('is_active = ?')
        updateParams.push(validatedData.is_active ? 1 : 0)
      }

      if (updateFields.length === 0) {
        return c.json({ error: 'No fields to update' }, 400)
      }

      updateFields.push('updated_at = ?')
      updateParams.push(Date.now())
      updateParams.push(id)

      const updateStmt = db.prepare(`
        UPDATE collections
        SET ${updateFields.join(', ')}
        WHERE id = ?
      `)

      await updateStmt.bind(...updateParams).run()

      // Clear cache
      try {
        await c.env.CACHE_KV.delete('cache:collections:all')
        await c.env.CACHE_KV.delete(`cache:collection:${existing.name}`)
      } catch (e) {
        console.error('Error clearing cache:', e)
      }

      return c.json({ message: 'Collection updated successfully' })
    } catch (error) {
      console.error('Error updating collection:', error)
      return c.json({ error: 'Failed to update collection' }, 500)
    }
})

/**
 * Delete collection
 * DELETE /admin/api/collections/:id
 */
adminApiRoutes.delete('/collections/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const db = c.env.DB

    // Check if collection exists
    const collectionStmt = db.prepare('SELECT name FROM collections WHERE id = ?')
    const collection = await collectionStmt.bind(id).first() as any

    if (!collection) {
      return c.json({ error: 'Collection not found' }, 404)
    }

    // Check if collection has content
    const contentStmt = db.prepare('SELECT COUNT(*) as count FROM content WHERE collection_id = ?')
    const contentResult = await contentStmt.bind(id).first() as any

    if (contentResult && contentResult.count > 0) {
      return c.json({
        error: `Cannot delete collection: it contains ${contentResult.count} content item(s). Delete all content first.`
      }, 400)
    }

    // Delete collection fields first
    const deleteFieldsStmt = db.prepare('DELETE FROM content_fields WHERE collection_id = ?')
    await deleteFieldsStmt.bind(id).run()

    // Delete collection
    const deleteStmt = db.prepare('DELETE FROM collections WHERE id = ?')
    await deleteStmt.bind(id).run()

    // Clear cache
    try {
      await c.env.CACHE_KV.delete('cache:collections:all')
      await c.env.CACHE_KV.delete(`cache:collection:${collection.name}`)
    } catch (e) {
      console.error('Error clearing cache:', e)
    }

    return c.json({ message: 'Collection deleted successfully' })
  } catch (error) {
    console.error('Error deleting collection:', error)
    return c.json({ error: 'Failed to delete collection' }, 500)
  }
})

// Migrations API endpoints
// Get migration status
adminApiRoutes.get('/migrations/status', async (c) => {
  try {
    const { MigrationService } = await import('../services/migrations')
    const db = c.env.DB
    const migrationService = new MigrationService(db)
    const status = await migrationService.getMigrationStatus()

    return c.json({
      success: true,
      data: status
    })
  } catch (error) {
    console.error('Error fetching migration status:', error)
    return c.json({
      success: false,
      error: 'Failed to fetch migration status'
    }, 500)
  }
})

// Run pending migrations
adminApiRoutes.post('/migrations/run', async (c) => {
  try {
    const user = c.get('user')

    // Only allow admin users to run migrations
    if (!user || user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized. Admin access required.'
      }, 403)
    }

    const { MigrationService } = await import('../services/migrations')
    const db = c.env.DB
    const migrationService = new MigrationService(db)
    const result = await migrationService.runPendingMigrations()

    return c.json({
      success: result.success,
      message: result.message,
      applied: result.applied
    })
  } catch (error) {
    console.error('Error running migrations:', error)
    return c.json({
      success: false,
      error: 'Failed to run migrations'
    }, 500)
  }
})

// Validate database schema
adminApiRoutes.get('/migrations/validate', async (c) => {
  try {
    const { MigrationService } = await import('../services/migrations')
    const db = c.env.DB
    const migrationService = new MigrationService(db)
    const validation = await migrationService.validateSchema()

    return c.json({
      success: true,
      data: validation
    })
  } catch (error) {
    console.error('Error validating schema:', error)
    return c.json({
      success: false,
      error: 'Failed to validate schema'
    }, 500)
  }
})

export default adminApiRoutes
