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
import { getCollectionRegistry } from '../services/collection-registry'

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

    // Get collections count from the in-memory registry (code-defined, non-internal).
    const userCollections = getCollectionRegistry()
      .listActive()
      .filter((r) => !r.internal)
    const collectionsCount = userCollections.length

    // Get content count. In the v3 greenfield schema content is document-backed only.
    // type_ids come from the same registry list (no JOIN against collections table).
    let contentCount = 0
    if (userCollections.length > 0) {
      try {
        const typeIds = userCollections.map((r) => r.name)
        const placeholders = typeIds.map(() => '?').join(',')
        const contentStmt = db.prepare(`
          SELECT COUNT(*) AS count
          FROM documents d
          WHERE d.is_current_draft = 1
            AND d.deleted_at IS NULL
            AND d.type_id IN (${placeholders})
        `).bind(...typeIds)
        const contentResult = await contentStmt.first()
        contentCount = (contentResult as any)?.count || 0
      } catch (error) {
        console.error('Error fetching content count:', error)
      }
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
      const usersStmt = db.prepare('SELECT COUNT(*) as count FROM auth_user WHERE is_active = 1')
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
  // activity_logs is not yet available — will be implemented as a plugin
  return c.json({
    data: [],
    count: 0,
    timestamp: new Date().toISOString()
  })
})

/**
 * Get all collections
 * GET /admin/api/collections
 */
adminApiRoutes.get('/collections', async (c) => {
  try {
    const search = c.req.query('search') || ''
    const includeInactive = c.req.query('includeInactive') === 'true'

    let records = getCollectionRegistry().list().filter((r) => !r.internal)
    if (!includeInactive) records = records.filter((r) => r.isActive !== false)

    if (search) {
      const needle = search.toLowerCase()
      records = records.filter(
        (r) =>
          r.name.toLowerCase().includes(needle) ||
          r.displayName.toLowerCase().includes(needle) ||
          (r.description ?? '').toLowerCase().includes(needle),
      )
    }

    const collections = records.map((r) => ({
      id: r.id,
      name: r.name,
      display_name: r.displayName,
      description: r.description ?? null,
      created_at: 0,
      updated_at: 0,
      is_active: r.isActive !== false,
      managed: r.managed !== false,
      field_count: Object.keys(r.schema?.properties ?? {}).length,
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
    // For code-defined collections, id == name. Try both for back-compat.
    const registry = getCollectionRegistry()
    const record = registry.getById(id) ?? registry.getByName(id)
    if (!record) {
      return c.json({ error: 'Collection not found' }, 404)
    }

    // Derive fields directly from the code-defined schema.
    const props = record.schema?.properties ?? {}
    const required = new Set(record.schema?.required ?? [])
    const fields = Object.entries(props).map(([fieldName, cfg], idx) => {
      const fieldCfg = cfg as any
      return {
        id: `${record.id}:${fieldName}`,
        field_name: fieldName,
        field_type: fieldCfg.type,
        field_label: fieldCfg.title ?? fieldName,
        field_options: fieldCfg,
        field_order: idx,
        is_required: required.has(fieldName),
        is_searchable: false,
        created_at: 0,
        updated_at: 0,
      }
    })

    return c.json({
      id: record.id,
      name: record.name,
      display_name: record.displayName,
      description: record.description ?? null,
      is_active: record.isActive !== false,
      managed: record.managed !== false,
      schema: record.schema,
      created_at: 0,
      updated_at: 0,
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

    // Resolve each requested id-or-name against the in-memory registry. For
    // code-defined collections id == name, so both lookup paths succeed.
    const registry = getCollectionRegistry()
    const matched = collectionParams
      .map((param) => registry.getById(param) ?? registry.getByName(param))
      .filter((r): r is NonNullable<typeof r> => !!r)

    // Dedupe by name.
    const seen = new Set<string>()
    const collections = matched.filter((r) => {
      if (seen.has(r.name)) return false
      seen.add(r.name)
      return true
    })

    if (collections.length === 0) {
      return c.json({ error: 'Collection not found' }, 404)
    }

    const collectionById = Object.fromEntries(
      collections.map((entry) => [
        entry.id,
        {
          id: entry.id,
          name: entry.name,
          display_name: entry.displayName,
        }
      ])
    )
    const collectionIds = collections.map((entry) => entry.id)
    const collectionNames = collections.map((entry) => entry.name)

    if (id) {
      // For code-defined collections, collection.id == type_id; no JOIN needed.
      const itemStmt = db.prepare(`
        SELECT d.root_id AS id, d.title, d.slug, d.type_id AS collection_id
        FROM documents d
        WHERE d.root_id = ?
          AND d.type_id IN (${collectionNames.map(() => '?').join(', ')})
          AND d.tenant_id = 'default'
          AND d.is_current_draft = 1
          AND d.deleted_at IS NULL
        LIMIT 1
      `)
      const item = await itemStmt.bind(id, ...collectionNames).first() as any

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

    let results
    const typePlaceholders = collectionNames.map(() => '?').join(', ')

    if (search) {
      const searchParam = `%${search}%`
      const stmt = db.prepare(`
        SELECT d.root_id AS id, d.title, d.slug,
               CASE WHEN d.is_published = 1 THEN 'published' ELSE 'draft' END AS status,
               d.updated_at * 1000 AS updated_at,
               d.type_id AS collection_id
        FROM documents d
        WHERE d.type_id IN (${typePlaceholders})
          AND d.tenant_id = 'default'
          AND d.is_current_draft = 1
          AND d.deleted_at IS NULL
          AND d.is_published = 1
          AND (d.title LIKE ? OR d.slug LIKE ?)
        ORDER BY d.updated_at DESC
        LIMIT ?
      `)
      const queryResults = await stmt
        .bind(...collectionNames, searchParam, searchParam, limit)
        .all()
      results = queryResults.results
    } else {
      const stmt = db.prepare(`
        SELECT d.root_id AS id, d.title, d.slug,
               CASE WHEN d.is_published = 1 THEN 'published' ELSE 'draft' END AS status,
               d.updated_at * 1000 AS updated_at,
               d.type_id AS collection_id
        FROM documents d
        WHERE d.type_id IN (${typePlaceholders})
          AND d.tenant_id = 'default'
          AND d.is_current_draft = 1
          AND d.deleted_at IS NULL
          AND d.is_published = 1
        ORDER BY d.updated_at DESC
        LIMIT ?
      `)
      const queryResults = await stmt
        .bind(...collectionNames, limit)
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

// Collections are code-only — POST/PATCH/DELETE return 405 so callers see a
// clear "method not allowed" instead of mutating state that no longer exists.
// See docs/ai/plans/drop-db-collections-plan.md (PR 3).
const collectionsReadOnly = (c: any) =>
  c.json(
    {
      error: 'Collections are code-defined and cannot be created, updated, or deleted via the admin API.',
      hint: 'Register collections via `registerCollections()` in your app entry point.',
    },
    405,
  )

adminApiRoutes.post('/collections', collectionsReadOnly)
adminApiRoutes.patch('/collections/:id', collectionsReadOnly)
adminApiRoutes.delete('/collections/:id', collectionsReadOnly)

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

// Migration execution is managed by Wrangler/D1, not by the running app.
adminApiRoutes.post('/migrations/run', async (c) => {
  try {
    const user = c.get('user')

    if (!user || user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized. Admin access required.'
      }, 403)
    }

    return c.json({
      success: false,
      message: 'Migrations are managed by Cloudflare D1. Run `wrangler d1 migrations apply DB --local` or `wrangler d1 migrations apply DB --remote`.',
      applied: [],
      errors: []
    }, 409)
  } catch (error) {
    console.error('Error running migrations:', error)
    const errorMessage = error instanceof Error ? error.message : String(error)
    return c.json({
      success: false,
      error: `Failed to run migrations: ${errorMessage}`,
      errors: [errorMessage]
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

adminApiRoutes.get('/users/search', async (c) => {
  try {
    const db = c.env.DB
    const q = (c.req.query('q') || '').trim()
    if (!q) {
      return c.json({ users: [] })
    }
    const like = `%${q}%`
    const stmt = db.prepare(
      `SELECT id, first_name, last_name, email FROM auth_user
       WHERE is_active = 1
         AND (first_name LIKE ? OR last_name LIKE ? OR email LIKE ?)
       ORDER BY first_name, last_name
       LIMIT 10`
    )
    const { results } = await stmt.bind(like, like, like).all()
    const users = (results as any[]).map((u) => ({
      id: u.id,
      name: `${u.first_name || ''} ${u.last_name || ''}`.trim() || u.email,
      email: u.email,
    }))
    return c.json({ users })
  } catch (error) {
    console.error('Error searching users:', error)
    return c.json({ users: [] }, 500)
  }
})

adminApiRoutes.get('/users/search-html', async (c) => {
  try {
    const db = c.env.DB
    const q = (c.req.query('q') || '').trim()
    const fieldId = (c.req.query('fieldId') || '').replace(/[^a-zA-Z0-9_-]/g, '')
    if (!q || !fieldId) {
      return c.html('')
    }
    const like = `%${q}%`
    const stmt = db.prepare(
      `SELECT id, first_name, last_name, email FROM auth_user
       WHERE is_active = 1
         AND (first_name LIKE ? OR last_name LIKE ? OR email LIKE ?)
       ORDER BY first_name, last_name
       LIMIT 10`
    )
    const { results } = await stmt.bind(like, like, like).all()
    if (!results.length) return c.html('')
    const items = (results as any[]).map((u) => {
      const name = `${u.first_name || ''} ${u.last_name || ''}`.trim() || u.email
      const safeName = name.replace(/'/g, "\\'")
      const safeEmail = (u.email as string).replace(/'/g, "\\'")
      return `<button type="button"
        class="w-full text-left px-3 py-2 text-sm hover:bg-zinc-700 border-b border-white/10 last:border-0 flex justify-between items-center"
        onclick="sonicSelectUser('${fieldId}','${u.id}','${safeName}')"
      ><span class="font-medium text-white">${name}</span><span class="text-xs text-zinc-400 ml-2">${u.email}</span></button>`
    }).join('')
    return c.html(items)
  } catch (error) {
    console.error('Error searching users (html):', error)
    return c.html('')
  }
})

adminApiRoutes.get('/users/:id', async (c) => {
  try {
    const db = c.env.DB
    const id = c.req.param('id')
    const result = await db.prepare(
      `SELECT id, first_name, last_name, email FROM auth_user WHERE id = ? AND is_active = 1 LIMIT 1`
    ).bind(id).first()
    if (!result) return c.json({ error: 'Not found' }, 404)
    const u = result as any
    const name = `${u.first_name || ''} ${u.last_name || ''}`.trim() || u.email
    return c.json({ id: u.id, name, email: u.email })
  } catch (error) {
    return c.json({ error: 'Failed' }, 500)
  }
})

export default adminApiRoutes
