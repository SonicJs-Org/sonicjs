import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { schemaDefinitions } from '../schemas'
import { getCacheService, CACHE_CONFIGS } from '../services'
import { QueryFilterBuilder, QueryFilter } from '../utils'
import { isPluginActive, optionalAuth, requireAuth, requireRole } from '../middleware'
import { canReadNonPublicContent, normalizePublicContentFilter } from './api-content-access-policy'
import { documentSecondsToMs, DocumentsService } from '../services/documents'
import { getCollectionRegistry, collectionRecordToRow } from '../services/collection-registry'
import { DocumentTypeRegistry } from '../services/document-type-registry'
import { dispatchHookEvent } from '../plugins/hooks/dispatch-event'
import type { HookActor } from '../plugins/hooks/catalog'
import { createDocumentSchema } from '../schemas/document'
import { getCoreVersion } from '../utils/version'

// Document columns the public list is allowed to ORDER BY. The legacy `content` table exposed
// collection_id; on documents that maps to type_id. Anything else (incl. nonexistent columns like a
// raw `collection_id`) would make SQLite throw → HTTP 500 (D31), so unknown plain columns are dropped.
// Dotted/JSON paths (e.g. `data.foo`) are always allowed — they compile to json_extract.
const DOC_SORTABLE_COLUMNS = new Set([
  'created_at', 'updated_at', 'published_at', 'scheduled_at', 'expires_at',
  'title', 'slug', 'status', 'sort_order', 'version_number', 'type_id',
])

// D32: read the caller's requested `status` (added by parseFromQuery, or via where-JSON / filter[]) so
// privileged callers can ask for published/draft/archived/deleted explicitly.
function extractRequestedStatus(group?: { and?: any[]; or?: any[] }): string | undefined {
  if (!group) return undefined
  const find = (arr?: any[]) => arr?.find(c => c?.field === 'status' && c?.operator === 'equals')?.value
  const v = find(group.and) ?? find(group.or)
  return typeof v === 'string' ? v : undefined
}

// Strip the given fields from a flat (and/or) where group so they never reach the documents SQL. Used
// for `status` (visibility is enforced below) and `collection_id` (no such column on documents — D31).
function stripFields(group: { and?: any[]; or?: any[] } | undefined, fields: Set<string>) {
  if (!group) return { and: [] as any[] }
  const filterArr = (arr?: any[]) => (arr ?? []).filter(c => !fields.has(c?.field))
  const out: any = {}
  const and = filterArr(group.and)
  const or = filterArr(group.or)
  if (and.length) out.and = and
  if (or.length) out.or = or
  return out
}

// D31/D44: translate `collection_id` sort → `type_id` and drop sort fields that aren't real document
// columns (a raw `collection_id` sort 500s). JSON-path sorts pass through unchanged.
function sanitizeDocSort(sort?: QueryFilter['sort']): QueryFilter['sort'] | undefined {
  if (!sort) return undefined
  const out = sort
    .map(s => ({ field: s.field === 'collection_id' ? 'type_id' : s.field, order: s.order }))
    .filter(s => s.field.includes('.') || DOC_SORTABLE_COLUMNS.has(s.field))
  return out.length ? out : undefined
}

// ─── Public content reads are document-backed (legacy `content` decommission, step 2) ────────────
// Re-target the QueryFilterBuilder at the `documents` table while preserving full filter parity:
// user data-field filters already compile to json_extract(data,'$.x') and carry over unchanged. We
// strip `status`/`collection_id` and instead control visibility + de-dupe to ONE row per root via
// is_published / is_current_draft (a superseded published row keeps status='published' but
// is_published=0, so status is not a safe key). type scoping uses type_id (== collection name).
function augmentFilterForDocuments(
  filter: QueryFilter,
  opts: { typeId?: string; typeIds?: string[]; role?: string },
): QueryFilter {
  const requestedStatus = extractRequestedStatus(filter.where)
  // Strip `status` (visibility is controlled below) and `collection_id` (D31: not a documents column).
  const where: any = stripFields(filter.where, new Set(['status', 'collection_id']))
  const and = where.and ? [...where.and] : []

  if (opts.typeId) and.push({ field: 'type_id', operator: 'equals', value: opts.typeId })
  else if (opts.typeIds && opts.typeIds.length) and.push({ field: 'type_id', operator: 'in', value: opts.typeIds })

  // Visibility + one-row-per-root. Anon can ONLY ever see the published revision (no fail-open),
  // regardless of any requested status. Privileged callers (admin/editor) may request a specific
  // status; the default (no status) is the current-draft working set (D32).
  if (!canReadNonPublicContent(opts.role)) {
    and.push({ field: 'deleted_at', operator: 'exists', value: false })
    and.push({ field: 'is_published', operator: 'equals', value: 1 })
  } else {
    switch (requestedStatus) {
      case 'published':
        and.push({ field: 'deleted_at', operator: 'exists', value: false })
        and.push({ field: 'is_published', operator: 'equals', value: 1 })
        break
      case 'draft':
        and.push({ field: 'deleted_at', operator: 'exists', value: false })
        and.push({ field: 'is_current_draft', operator: 'equals', value: 1 })
        and.push({ field: 'is_published', operator: 'equals', value: 0 })
        break
      case 'archived':
        and.push({ field: 'deleted_at', operator: 'exists', value: false })
        and.push({ field: 'is_current_draft', operator: 'equals', value: 1 })
        and.push({ field: 'status', operator: 'equals', value: 'archived' })
        break
      case 'deleted':
        and.push({ field: 'deleted_at', operator: 'exists', value: true })
        and.push({ field: 'is_current_draft', operator: 'equals', value: 1 })
        break
      default:
        and.push({ field: 'deleted_at', operator: 'exists', value: false })
        and.push({ field: 'is_current_draft', operator: 'equals', value: 1 })
    }
  }

  return { ...filter, where: { ...where, and }, sort: sanitizeDocSort(filter.sort) }
}

function mapDocRowToContent(row: any, collectionId: string | null) {
  return {
    id: row.root_id,
    title: row.title,
    slug: row.slug,
    status: row.status,
    collectionId,
    data: row.data ? JSON.parse(row.data) : {},
    // D29: document timestamps are SECONDS; the legacy `content` API contract is MILLISECONDS.
    created_at: documentSecondsToMs(row.created_at),
    updated_at: documentSecondsToMs(row.updated_at),
  }
}
import apiContentCrudRoutes, { resolveDocBacking, slugify } from './api-content-crud'
import type { Bindings, Variables as AppVariables } from '../app'

// Extend Variables with API-specific fields
interface Variables extends AppVariables {
  startTime: number
  cacheEnabled?: boolean
}

const apiRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Add timing middleware
apiRoutes.use('*', async (c, next) => {
  const startTime = Date.now()
  c.set('startTime', startTime)
  await next()
  const totalTime = Date.now() - startTime
  c.header('X-Response-Time', `${totalTime}ms`)
})

// Check if cache plugin is active
apiRoutes.use('*', async (c, next) => {
  const cacheEnabled = await isPluginActive(c.env.DB, 'core-cache')
  c.set('cacheEnabled', cacheEnabled)
  await next()
})

// Add CORS middleware
apiRoutes.use('*', cors({
  origin: (origin, c) => {
    const allowed = (c.env as any)?.CORS_ORIGINS as string | undefined
    if (!allowed) return null // No env var = reject cross-origin (secure default)
    const list = allowed.split(',').map((s: string) => s.trim())
    return list.includes(origin) ? origin : null
  },
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
}))

// Helper function to add timing metadata
function addTimingMeta(c: any, meta: any = {}, executionStartTime?: number) {
  const totalTime = Date.now() - c.get('startTime')
  const executionTime = executionStartTime ? Date.now() - executionStartTime : undefined

  return {
    ...meta,
    timing: {
      total: totalTime,
      execution: executionTime,
      unit: 'ms'
    }
  }
}

// Root endpoint - OpenAPI 3.0.0 specification
apiRoutes.get('/', (c) => {
  const baseUrl = new URL(c.req.url)
  const serverUrl = `${baseUrl.protocol}//${baseUrl.host}`

  return c.json({
    openapi: '3.0.0',
    info: {
      title: 'SonicJS AI API',
      version: getCoreVersion(),
      description: 'RESTful API for SonicJS headless CMS - a modern, AI-powered content management system built on Cloudflare Workers',
      contact: {
        name: 'SonicJS Support',
        url: `${serverUrl}/docs`,
        email: 'support@sonicjs.com'
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT'
      }
    },
    servers: [
      {
        url: serverUrl,
        description: 'Current server'
      }
    ],
    paths: {
      '/api/': {
        get: {
          summary: 'API Information',
          description: 'Returns OpenAPI specification for the SonicJS API',
          operationId: 'getApiInfo',
          tags: ['System'],
          responses: {
            '200': {
              description: 'OpenAPI specification',
              content: {
                'application/json': {
                  schema: { type: 'object' }
                }
              }
            }
          }
        }
      },
      '/api/health': {
        get: {
          summary: 'Health Check',
          description: 'Returns API health status and available schemas',
          operationId: 'getHealth',
          tags: ['System'],
          responses: {
            '200': {
              description: 'Health status',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      status: { type: 'string', example: 'healthy' },
                      timestamp: { type: 'string', format: 'date-time' },
                      schemas: { type: 'array', items: { type: 'string' } }
                    }
                  }
                }
              }
            }
          }
        }
      },
      '/api/collections': {
        get: {
          summary: 'List Collections',
          description: 'Returns all active collections with their schemas',
          operationId: 'getCollections',
          tags: ['Content'],
          responses: {
            '200': {
              description: 'List of collections',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: {
                        type: 'array',
                        items: {
                          type: 'object',
                          properties: {
                            id: { type: 'string' },
                            name: { type: 'string' },
                            display_name: { type: 'string' },
                            schema: { type: 'object' },
                            is_active: { type: 'integer' }
                          }
                        }
                      },
                      meta: { type: 'object' }
                    }
                  }
                }
              }
            }
          }
        }
      },
      '/api/collections/{collection}/content': {
        get: {
          summary: 'Get Collection Content',
          description: 'Returns content items from a specific collection with filtering support. Anonymous, viewer, and author requests are restricted to published content; admin and editor requests may query other statuses.',
          operationId: 'getCollectionContent',
          tags: ['Content'],
          parameters: [
            {
              name: 'collection',
              in: 'path',
              required: true,
              schema: { type: 'string' },
              description: 'Collection name'
            },
            {
              name: 'limit',
              in: 'query',
              schema: { type: 'integer', default: 50, maximum: 1000 },
              description: 'Maximum number of items to return'
            },
            {
              name: 'offset',
              in: 'query',
              schema: { type: 'integer', default: 0 },
              description: 'Number of items to skip'
            },
            {
              name: 'status',
              in: 'query',
              schema: { type: 'string', enum: ['draft', 'published', 'archived'] },
              description: 'Filter by content status. Anonymous, viewer, and author requests are limited to published content.'
            }
          ],
          responses: {
            '200': {
              description: 'List of content items',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { type: 'object' } },
                      meta: { type: 'object' }
                    }
                  }
                }
              }
            },
            '404': {
              description: 'Collection not found'
            }
          }
        }
      },
      '/api/content': {
        get: {
          summary: 'List Content',
          description: 'Returns content items with advanced filtering support. Anonymous, viewer, and author requests are restricted to published content; admin and editor requests may query other statuses.',
          operationId: 'getContent',
          tags: ['Content'],
          parameters: [
            {
              name: 'collection',
              in: 'query',
              schema: { type: 'string' },
              description: 'Filter by collection name'
            },
            {
              name: 'limit',
              in: 'query',
              schema: { type: 'integer', default: 50, maximum: 1000 },
              description: 'Maximum number of items to return'
            },
            {
              name: 'offset',
              in: 'query',
              schema: { type: 'integer', default: 0 },
              description: 'Number of items to skip'
            },
            {
              name: 'status',
              in: 'query',
              schema: { type: 'string', enum: ['draft', 'published', 'archived'] },
              description: 'Filter by content status. Anonymous, viewer, and author requests are limited to published content.'
            }
          ],
          responses: {
            '200': {
              description: 'List of content items',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { type: 'object' } },
                      meta: { type: 'object' }
                    }
                  }
                }
              }
            }
          }
        },
        post: {
          summary: 'Create Content',
          description: 'Creates a new content item',
          operationId: 'createContent',
          tags: ['Content'],
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['collection_id', 'title'],
                  properties: {
                    collection_id: { type: 'string' },
                    title: { type: 'string' },
                    slug: { type: 'string' },
                    status: { type: 'string', enum: ['draft', 'published', 'archived'] },
                    data: { type: 'object' }
                  }
                }
              }
            }
          },
          responses: {
            '201': { description: 'Content created successfully' },
            '400': { description: 'Invalid request body' },
            '401': { description: 'Unauthorized' }
          }
        }
      },
      '/api/content/{id}': {
        get: {
          summary: 'Get Content by ID',
          description: 'Returns a specific content item by ID',
          operationId: 'getContentById',
          tags: ['Content'],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string' },
              description: 'Content item ID'
            }
          ],
          responses: {
            '200': { description: 'Content item' },
            '404': { description: 'Content not found' }
          }
        },
        put: {
          summary: 'Update Content',
          description: 'Updates an existing content item',
          operationId: 'updateContent',
          tags: ['Content'],
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string' },
              description: 'Content item ID'
            }
          ],
          responses: {
            '200': { description: 'Content updated successfully' },
            '401': { description: 'Unauthorized' },
            '404': { description: 'Content not found' }
          }
        },
        delete: {
          summary: 'Delete Content',
          description: 'Deletes a content item',
          operationId: 'deleteContent',
          tags: ['Content'],
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'string' },
              description: 'Content item ID'
            }
          ],
          responses: {
            '200': { description: 'Content deleted successfully' },
            '401': { description: 'Unauthorized' },
            '404': { description: 'Content not found' }
          }
        }
      },
      '/api/media': {
        get: {
          summary: 'List Media',
          description: 'Returns all media files with pagination',
          operationId: 'getMedia',
          tags: ['Media'],
          responses: {
            '200': { description: 'List of media files' }
          }
        }
      },
      '/api/media/upload': {
        post: {
          summary: 'Upload Media',
          description: 'Uploads a new media file to R2 storage',
          operationId: 'uploadMedia',
          tags: ['Media'],
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'multipart/form-data': {
                schema: {
                  type: 'object',
                  properties: {
                    file: { type: 'string', format: 'binary' }
                  }
                }
              }
            }
          },
          responses: {
            '201': { description: 'Media uploaded successfully' },
            '401': { description: 'Unauthorized' }
          }
        }
      }
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },
      schemas: {
        Content: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            title: { type: 'string' },
            slug: { type: 'string' },
            status: { type: 'string', enum: ['draft', 'published', 'archived'] },
            collectionId: { type: 'string', format: 'uuid' },
            data: { type: 'object' },
            created_at: { type: 'integer' },
            updated_at: { type: 'integer' }
          }
        },
        Collection: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            name: { type: 'string' },
            display_name: { type: 'string' },
            description: { type: 'string' },
            schema: { type: 'object' },
            is_active: { type: 'integer' }
          }
        },
        Media: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            filename: { type: 'string' },
            mimetype: { type: 'string' },
            size: { type: 'integer' },
            url: { type: 'string' }
          }
        },
        Error: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            details: { type: 'string' }
          }
        }
      }
    },
    tags: [
      { name: 'System', description: 'System and health endpoints' },
      { name: 'Content', description: 'Content management operations' },
      { name: 'Media', description: 'Media file operations' }
    ]
  })
})

// Health check endpoint
apiRoutes.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    schemas: schemaDefinitions.map(s => s.name)
  })
})

// Basic collections endpoint
apiRoutes.get('/collections', async (c) => {
  const executionStart = Date.now()

  try {
    const db = c.env.DB
    const cacheEnabled = c.get('cacheEnabled')
    const cache = getCacheService(CACHE_CONFIGS.api!)
    const cacheKey = cache.generateKey('collections', 'all')

    // Use cache only if cache plugin is active
    if (cacheEnabled) {
      const cacheResult = await cache.getWithSource<any>(cacheKey)
      if (cacheResult.hit && cacheResult.data) {
        // Add cache headers
        c.header('X-Cache-Status', 'HIT')
        c.header('X-Cache-Source', cacheResult.source)
        if (cacheResult.ttl) {
          c.header('X-Cache-TTL', Math.floor(cacheResult.ttl).toString())
        }

        // Add cache info and timing to meta
        const dataWithMeta = {
          ...cacheResult.data,
          meta: addTimingMeta(c, {
            ...cacheResult.data.meta,
            cache: {
              hit: true,
              source: cacheResult.source,
              ttl: cacheResult.ttl ? Math.floor(cacheResult.ttl) : undefined
            }
          }, executionStart)
        }

        return c.json(dataWithMeta)
      }
    }

    // Cache miss — read from the in-memory registry (code-defined collections).
    c.header('X-Cache-Status', 'MISS')
    c.header('X-Cache-Source', 'registry')

    const records = getCollectionRegistry()
      .listActive()
      .filter((r) => !r.internal)
    const transformedResults = records.map(collectionRecordToRow)

    const responseData = {
      data: transformedResults,
      meta: addTimingMeta(c, {
        count: transformedResults.length,
        timestamp: new Date().toISOString(),
        cache: {
          hit: false,
          source: 'registry'
        }
      }, executionStart)
    }

    // Cache the response only if cache plugin is enabled
    if (cacheEnabled) {
      await cache.set(cacheKey, responseData)
    }

    return c.json(responseData)
  } catch (error) {
    console.error('Error fetching collections:', error)
    return c.json({ error: 'Failed to fetch collections' }, 500)
  }
})

// Basic content endpoint with advanced filtering
apiRoutes.get('/content', optionalAuth(), async (c) => {
  const executionStart = Date.now()

  try {
    const db = c.env.DB
    const queryParams = c.req.query()

    const role = c.get('user')?.role

    // Resolve collection scoping to document type ids (== collection name). Build a name→collectionId
    // map so the response keeps a stable collectionId field.
    const collIdByName = new Map<string, string>()
    let typeId: string | undefined
    let typeIds: string[] | undefined
    const registry = getCollectionRegistry()
    if (queryParams.collection) {
      const collectionName = queryParams.collection
      const record = registry.getByName(collectionName)
      if (!record || record.isActive === false) {
        return c.json({
          data: [],
          meta: addTimingMeta(c, { count: 0, timestamp: new Date().toISOString(), message: `Collection '${collectionName}' not found` }, executionStart)
        })
      }
      typeId = collectionName
      collIdByName.set(collectionName, record.id)
      delete queryParams.collection
    } else if (queryParams.collection_id) {
      // D31: legacy `?collection_id=<id>` — for code-defined collections, id == name.
      const record = registry.getById(queryParams.collection_id)
      if (!record || record.isActive === false) {
        return c.json({
          data: [],
          meta: addTimingMeta(c, { count: 0, timestamp: new Date().toISOString(), message: `Collection '${queryParams.collection_id}' not found` }, executionStart)
        })
      }
      typeId = record.name
      collIdByName.set(record.name, record.id)
    } else {
      const records = registry.listActive().filter((r) => !r.internal)
      typeIds = records.map((r) => { collIdByName.set(r.name, r.id); return r.name })
    }

    // Parse the user filter (data-field filters carry over as json_extract), then re-target to
    // the documents table with type + visibility scoping (one row per root).
    const filter: QueryFilter = QueryFilterBuilder.parseFromQuery(queryParams)
    const normalizedFilter = augmentFilterForDocuments(filter, { typeId, typeIds, role })
    if (!normalizedFilter.limit) normalizedFilter.limit = 50
    normalizedFilter.limit = Math.min(normalizedFilter.limit, 1000) // Max 1000

    // Build SQL query from filter
    const builder = new QueryFilterBuilder()
    const queryResult = builder.build('documents', normalizedFilter)

    // Check for query building errors
    if (queryResult.errors.length > 0) {
      return c.json({
        error: 'Invalid filter parameters',
        details: queryResult.errors
      }, 400)
    }

    // Only use cache if cache plugin is active
    const cacheEnabled = c.get('cacheEnabled')
    const cache = getCacheService(CACHE_CONFIGS.api!)
    const cacheKey = cache.generateKey('content-filtered', JSON.stringify({ filter: normalizedFilter, query: queryResult.sql }))

    if (cacheEnabled) {
      const cacheResult = await cache.getWithSource<any>(cacheKey)
      if (cacheResult.hit && cacheResult.data) {
        // Add cache headers
        c.header('X-Cache-Status', 'HIT')
        c.header('X-Cache-Source', cacheResult.source)
        if (cacheResult.ttl) {
          c.header('X-Cache-TTL', Math.floor(cacheResult.ttl).toString())
        }

        // Add cache info and timing to meta
        const dataWithMeta = {
          ...cacheResult.data,
          meta: addTimingMeta(c, {
            ...cacheResult.data.meta,
            cache: {
              hit: true,
              source: cacheResult.source,
              ttl: cacheResult.ttl ? Math.floor(cacheResult.ttl) : undefined
            }
          }, executionStart)
        }

        return c.json(dataWithMeta)
      }
    }

    // Cache miss - fetch from database
    c.header('X-Cache-Status', 'MISS')
    c.header('X-Cache-Source', 'database')

    // Execute query with parameters
    const stmt = db.prepare(queryResult.sql)
    const boundStmt = queryResult.params.length > 0
      ? stmt.bind(...queryResult.params)
      : stmt

    const { results } = await boundStmt.all()

    // Transform document rows to the public content shape (id == document root id).
    const transformedResults = results.map((row: any) => mapDocRowToContent(row, collIdByName.get(row.type_id) ?? null))

    const responseData = {
      data: transformedResults,
      meta: addTimingMeta(c, {
        count: results.length,
        timestamp: new Date().toISOString(),
        // D44: echo the caller's filter with the access policy applied (status=published forced for
        // anonymous callers — the visible enforcement proof), NOT the internal doc-augmented where-tree.
        filter: normalizePublicContentFilter(filter, role),
        cache: {
          hit: false,
          source: 'database'
        }
      }, executionStart)
    }

    // Cache the response only if cache is enabled
    if (cacheEnabled) {
      await cache.set(cacheKey, responseData)
    }

    return c.json(responseData)
  } catch (error) {
    console.error('Error fetching content:', error)
    return c.json({
      error: 'Failed to fetch content',
      details: error instanceof Error ? error.message : String(error)
    }, 500)
  }
})

// Collection-specific routes with advanced filtering
apiRoutes.get('/collections/:collection/content', optionalAuth(), async (c) => {
  const executionStart = Date.now()

  try {
    const collection = c.req.param('collection')
    const db = c.env.DB
    const queryParams = c.req.query()

    // First check if collection exists in the in-memory registry
    const record = getCollectionRegistry().getBySlugOrName(collection!)
    if (!record || record.isActive === false) {
      return c.json({ error: 'Collection not found' }, 404)
    }

    const collIdByName = new Map<string, string>()
    collIdByName.set(collection!, record.id)

    // Parse the user filter, re-target to documents scoped to this collection's type + visibility.
    // type_id == the collection name; one row per root via is_published / is_current_draft.
    const role = c.get('user')?.role
    const filter: QueryFilter = QueryFilterBuilder.parseFromQuery(queryParams)
    const normalizedFilter = augmentFilterForDocuments(filter, { typeId: collection, role })

    if (!normalizedFilter.limit) {
      normalizedFilter.limit = 50
    }
    normalizedFilter.limit = Math.min(normalizedFilter.limit, 1000)

    // Build SQL query from filter
    const builder = new QueryFilterBuilder()
    const queryResult = builder.build('documents', normalizedFilter)

    // Check for query building errors
    if (queryResult.errors.length > 0) {
      return c.json({
        error: 'Invalid filter parameters',
        details: queryResult.errors
      }, 400)
    }

    // Generate cache key
    const cacheEnabled = c.get('cacheEnabled')
    const cache = getCacheService(CACHE_CONFIGS.api!)
    const cacheKey = cache.generateKey('collection-content-filtered', `${collection}:${JSON.stringify({ filter: normalizedFilter, query: queryResult.sql })}`)

    // Only check cache if plugin is enabled
    if (cacheEnabled) {
      const cacheResult = await cache.getWithSource<any>(cacheKey)
      if (cacheResult.hit && cacheResult.data) {
        // Add cache headers
        c.header('X-Cache-Status', 'HIT')
        c.header('X-Cache-Source', cacheResult.source)
        if (cacheResult.ttl) {
          c.header('X-Cache-TTL', Math.floor(cacheResult.ttl).toString())
        }

        // Add cache info and timing to meta
        const dataWithMeta = {
          ...cacheResult.data,
          meta: addTimingMeta(c, {
            ...cacheResult.data.meta,
            cache: {
              hit: true,
              source: cacheResult.source,
              ttl: cacheResult.ttl ? Math.floor(cacheResult.ttl) : undefined
            }
          }, executionStart)
        }

        return c.json(dataWithMeta)
      }
    }

    // Cache miss - fetch from database
    c.header('X-Cache-Status', 'MISS')
    c.header('X-Cache-Source', 'database')

    // Execute query with parameters
    const stmt = db.prepare(queryResult.sql)
    const boundStmt = queryResult.params.length > 0
      ? stmt.bind(...queryResult.params)
      : stmt

    const { results } = await boundStmt.all()

    // Transform document rows to the public content shape (id == document root id).
    const transformedResults = results.map((row: any) => mapDocRowToContent(row, collIdByName.get(row.type_id) ?? null))

    const responseData = {
      data: transformedResults,
      meta: addTimingMeta(c, {
        collection: collectionRecordToRow(record),
        count: results.length,
        timestamp: new Date().toISOString(),
        // D44: echo the caller's filter with the access policy applied (status=published forced for
        // anonymous callers — the visible enforcement proof), NOT the internal doc-augmented where-tree.
        filter: normalizePublicContentFilter(filter, role),
        cache: {
          hit: false,
          source: 'registry'
        }
      }, executionStart)
    }

    // Cache the response only if cache plugin is enabled
    if (cacheEnabled) {
      await cache.set(cacheKey, responseData)
    }

    return c.json(responseData)
  } catch (error) {
    console.error('Error fetching content:', error)
    return c.json({
      error: 'Failed to fetch content',
      details: error instanceof Error ? error.message : String(error)
    }, 500)
  }
})

// Mount CRUD routes for content
apiRoutes.route('/content', apiContentCrudRoutes)

// ─── Per-collection shorthand routes: GET /api/:collection, GET /api/:collection/:id,
//     POST /api/:collection, PUT /api/:collection/:id, DELETE /api/:collection/:id ──────────────
// Wildcards must come after all specific routes above.

// GET /api/:collection — list items (shorthand for /api/collections/:collection/content)
apiRoutes.get('/:collection', optionalAuth(), async (c) => {
  const executionStart = Date.now()
  try {
    const collection = c.req.param('collection')
    const db = c.env.DB
    const queryParams = c.req.query()

    const record = getCollectionRegistry().getBySlugOrName(collection!)
    if (!record || record.isActive === false) {
      return c.json({ error: 'Collection not found' }, 404)
    }

    const collIdByName = new Map<string, string>()
    collIdByName.set(record.name, record.id)

    const role = c.get('user')?.role
    const filter: QueryFilter = QueryFilterBuilder.parseFromQuery(queryParams)
    const normalizedFilter = augmentFilterForDocuments(filter, { typeId: record.name, role })
    if (!normalizedFilter.limit) normalizedFilter.limit = 50
    normalizedFilter.limit = Math.min(normalizedFilter.limit, 1000)

    const builder = new QueryFilterBuilder()
    const queryResult = builder.build('documents', normalizedFilter)

    if (queryResult.errors.length > 0) {
      return c.json({ error: 'Invalid filter parameters', details: queryResult.errors }, 400)
    }

    const cacheEnabled = c.get('cacheEnabled')
    const cache = getCacheService(CACHE_CONFIGS.api!)
    const cacheKey = cache.generateKey('collection-content-filtered', `${collection}:${JSON.stringify({ filter: normalizedFilter, query: queryResult.sql })}`)

    if (cacheEnabled) {
      const cacheResult = await cache.getWithSource<any>(cacheKey)
      if (cacheResult.hit && cacheResult.data) {
        c.header('X-Cache-Status', 'HIT')
        c.header('X-Cache-Source', cacheResult.source)
        if (cacheResult.ttl) c.header('X-Cache-TTL', Math.floor(cacheResult.ttl).toString())
        return c.json({ ...cacheResult.data, meta: addTimingMeta(c, { ...cacheResult.data.meta, cache: { hit: true, source: cacheResult.source, ttl: cacheResult.ttl ? Math.floor(cacheResult.ttl) : undefined } }, executionStart) })
      }
    }

    c.header('X-Cache-Status', 'MISS')
    c.header('X-Cache-Source', 'database')

    const stmt = db.prepare(queryResult.sql)
    const boundStmt = queryResult.params.length > 0 ? stmt.bind(...queryResult.params) : stmt
    const { results } = await boundStmt.all()

    const transformedResults = results.map((row: any) => mapDocRowToContent(row, collIdByName.get(row.type_id) ?? null))
    const responseData = {
      data: transformedResults,
      meta: addTimingMeta(c, {
        collection: collectionRecordToRow(record),
        count: results.length,
        timestamp: new Date().toISOString(),
        filter: normalizePublicContentFilter(filter, role),
        cache: { hit: false, source: 'database' },
      }, executionStart)
    }

    if (cacheEnabled) await cache.set(cacheKey, responseData)
    return c.json(responseData)
  } catch (error) {
    console.error('Error fetching collection content:', error)
    return c.json({ error: 'Failed to fetch content', details: error instanceof Error ? error.message : String(error) }, 500)
  }
})

// GET /api/:collection/:id — single item by root_id, scoped to collection
apiRoutes.get('/:collection/:id', optionalAuth(), async (c) => {
  try {
    const collection = c.req.param('collection')
    const id = c.req.param('id')
    const db = c.env.DB

    const record = getCollectionRegistry().getBySlugOrName(collection!)
    if (!record || record.isActive === false) {
      return c.json({ error: 'Collection not found' }, 404)
    }

    const privileged = canReadNonPublicContent(c.get('user')?.role)
    const docRow = await db
      .prepare(
        privileged
          ? "SELECT * FROM documents WHERE root_id = ? AND type_id = ? AND tenant_id = 'default' AND is_current_draft = 1 AND deleted_at IS NULL"
          : "SELECT * FROM documents WHERE root_id = ? AND type_id = ? AND tenant_id = 'default' AND is_published = 1 AND deleted_at IS NULL",
      )
      .bind(id, record.name)
      .first() as any

    if (!docRow) return c.json({ error: 'Content not found' }, 404)

    const coll = getCollectionRegistry().getByName(docRow.type_id)
    const transformedContent = {
      id: docRow.root_id,
      title: docRow.title,
      slug: docRow.slug,
      status: docRow.status,
      collectionId: coll?.id ?? docRow.type_id,
      data: docRow.data ? JSON.parse(docRow.data) : {},
      created_at: documentSecondsToMs(docRow.created_at),
      updated_at: documentSecondsToMs(docRow.updated_at),
    }

    dispatchHookEvent(c, 'content:read', { collection: docRow.type_id, id: docRow.root_id, data: transformedContent.data }, 'fire-and-forget')
    return c.json({ data: transformedContent })
  } catch (error) {
    console.error('Error fetching content:', error)
    return c.json({ error: 'Failed to fetch content', details: error instanceof Error ? error.message : String(error) }, 500)
  }
})

// POST /api/:collection — create item in collection
apiRoutes.post('/:collection', requireAuth(), requireRole(['admin', 'editor', 'author']), async (c) => {
  try {
    const collection = c.req.param('collection')
    const db = c.env.DB
    const user = c.get('user')
    const body = await c.req.json()
    const { title, slug, status, data } = body

    if (!title) return c.json({ error: 'title is required' }, 400)

    const backing = await resolveDocBacking(db, collection!)
    if (!backing) return c.json({ error: 'Collection not found' }, 404)

    let finalSlug = slugify(slug || title) || title.toLowerCase().replace(/\s+/g, '-')

    const dup = await db
      .prepare("SELECT root_id FROM documents WHERE type_id = ? AND tenant_id = 'default' AND (is_current_draft = 1 OR is_published = 1) AND deleted_at IS NULL AND slug = ?")
      .bind(backing.coll.name, finalSlug)
      .first()
    if (dup) return c.json({ error: 'A content item with this slug already exists in this collection' }, 409)

    const actor: HookActor | undefined = user ? { id: user.userId, email: user.email ?? '', role: user.role } : undefined
    let hookData = data || {}
    try {
      const beforePayload = await dispatchHookEvent(c, 'content:before:create', { collection: backing.coll.name, data: { title, slug: finalSlug, status: status || 'draft', ...hookData }, user: actor }, 'in-band')
      hookData = typeof beforePayload?.data === 'object' ? beforePayload.data : hookData
    } catch (err) {
      return c.json({ error: 'Write cancelled by plugin', details: String(err) }, 400)
    }

    const svc = new DocumentsService(db, { queryableFields: backing.docType.queryableFields ?? [], typeSchemaVersion: backing.docType.schemaVersion ?? 1, maxVersionsPerRoot: backing.docType.settings?.maxVersionsPerRoot ?? 50, tenantId: 'default' })
    const doc = await svc.create(createDocumentSchema.parse({ typeId: backing.coll.name, tenantId: 'default', locale: 'default', title, slug: finalSlug, data: hookData, publishOnCreate: (status || 'draft') === 'published' }), user?.userId)

    const cache = getCacheService(CACHE_CONFIGS.api!)
    await cache.invalidate('content-filtered:*')
    await cache.invalidate('collection-content-filtered:*')
    dispatchHookEvent(c, 'content:after:create', { collection: backing.coll.name, id: doc.rootId, data: doc.data ?? {}, user: actor }, 'fire-and-forget')

    return c.json({ data: { id: doc.rootId, title: doc.title, slug: doc.slug, status: doc.status, collectionId: backing.coll.id, data: doc.data, created_at: documentSecondsToMs(doc.createdAt), updated_at: documentSecondsToMs(doc.updatedAt) } }, 201)
  } catch (error) {
    console.error('Error creating content:', error)
    return c.json({ error: 'Failed to create content', details: error instanceof Error ? error.message : String(error) }, 500)
  }
})

// PUT /api/:collection/:id — update item
apiRoutes.put('/:collection/:id', requireAuth(), requireRole(['admin', 'editor', 'author']), async (c) => {
  try {
    const collection = c.req.param('collection')
    const id = c.req.param('id')
    const db = c.env.DB
    const user = c.get('user')
    const body = await c.req.json()

    const collRecord = getCollectionRegistry().getBySlugOrName(collection!)
    const typeName = collRecord?.name ?? collection!

    const docRow = await db
      .prepare("SELECT root_id, type_id FROM documents WHERE root_id = ? AND type_id = ? AND tenant_id = 'default' AND is_current_draft = 1 AND deleted_at IS NULL")
      .bind(id, typeName)
      .first() as any
    if (!docRow) return c.json({ error: 'Content not found' }, 404)

    const actor: HookActor | undefined = user ? { id: user.userId, email: user.email ?? '', role: user.role } : undefined
    let hookData = body.data
    try {
      const beforePayload = await dispatchHookEvent(c, 'content:before:update', { collection: docRow.type_id, id, data: { title: body.title, slug: body.slug, status: body.status, ...(body.data || {}) }, user: actor }, 'in-band')
      if (typeof beforePayload?.data === 'object') hookData = beforePayload.data
    } catch (err) {
      return c.json({ error: 'Write cancelled by plugin', details: String(err) }, 400)
    }

    const docType = await new DocumentTypeRegistry(db).findById(docRow.type_id)
    const svc = new DocumentsService(db, { queryableFields: docType?.queryableFields ?? [], typeSchemaVersion: docType?.schemaVersion ?? 1, maxVersionsPerRoot: docType?.settings?.maxVersionsPerRoot ?? 50, tenantId: 'default' })
    const input: any = {}
    if (body.title !== undefined) input.title = body.title
    if (body.slug !== undefined) input.slug = slugify(body.slug)
    if (hookData !== undefined) input.data = hookData
    const newDraft = await svc.saveDraft(id!, input, user?.userId)
    const pub = await db.prepare("SELECT id FROM documents WHERE root_id = ? AND is_published = 1 AND tenant_id = 'default'").bind(id).first() as any
    const wasPublished = !!pub
    if (body.status === 'published' || (body.status === undefined && pub)) {
      await svc.publish(newDraft.id, user?.userId)
    } else if (body.status === 'draft' && pub) {
      await svc.unpublish(pub.id)
    }

    const cache = getCacheService(CACHE_CONFIGS.api!)
    await cache.invalidate('content-filtered:*')
    await cache.invalidate('collection-content-filtered:*')
    const coll = getCollectionRegistry().getByName(docRow.type_id)
    const saved = await db.prepare('SELECT * FROM documents WHERE id = ?').bind(newDraft.id).first() as any
    const savedData = saved?.data ? JSON.parse(saved.data) : {}

    dispatchHookEvent(c, 'content:after:update', { collection: docRow.type_id, id, data: savedData, user: actor }, 'fire-and-forget')
    const nowPublished = body.status === 'published' || (body.status === undefined && wasPublished)
    if (nowPublished && !wasPublished) dispatchHookEvent(c, 'content:after:publish', { collection: docRow.type_id, id, data: savedData, user: actor }, 'fire-and-forget')

    return c.json({ data: { id: saved.root_id, title: saved.title, slug: saved.slug, status: saved.status, collectionId: coll?.id ?? docRow.type_id, data: savedData, created_at: documentSecondsToMs(saved.created_at), updated_at: documentSecondsToMs(saved.updated_at) } })
  } catch (error) {
    console.error('Error updating content:', error)
    return c.json({ error: 'Failed to update content', details: error instanceof Error ? error.message : String(error) }, 500)
  }
})

// DELETE /api/:collection/:id — delete item
apiRoutes.delete('/:collection/:id', requireAuth(), requireRole(['admin', 'editor', 'author']), async (c) => {
  try {
    const collection = c.req.param('collection')
    const id = c.req.param('id')
    const db = c.env.DB
    const user = c.get('user')

    const collRecord = getCollectionRegistry().getBySlugOrName(collection!)
    const typeName = collRecord?.name ?? collection!
    const docRow = await db.prepare("SELECT type_id FROM documents WHERE root_id = ? AND type_id = ? AND tenant_id = 'default' AND deleted_at IS NULL LIMIT 1").bind(id, typeName).first() as any
    if (!docRow) return c.json({ error: 'Content not found' }, 404)

    const actor: HookActor | undefined = user ? { id: user.userId, email: user.email ?? '', role: user.role } : undefined
    try {
      await dispatchHookEvent(c, 'content:before:delete', { collection: docRow.type_id, id, data: {}, user: actor }, 'in-band')
    } catch (err) {
      return c.json({ error: 'Delete cancelled by plugin', details: String(err) }, 400)
    }

    const now = Math.floor(Date.now() / 1000)
    await db.prepare("UPDATE documents SET deleted_at = ?, updated_at = ? WHERE root_id = ? AND tenant_id = 'default'").bind(now, now, id).run()
    const cache = getCacheService(CACHE_CONFIGS.api!)
    await cache.invalidate('content-filtered:*')
    await cache.invalidate('collection-content-filtered:*')
    dispatchHookEvent(c, 'content:after:delete', { collection: docRow.type_id, id, data: {}, user: actor }, 'fire-and-forget')

    return c.json({ success: true })
  } catch (error) {
    console.error('Error deleting content:', error)
    return c.json({ error: 'Failed to delete content', details: error instanceof Error ? error.message : String(error) }, 500)
  }
})

export default apiRoutes
