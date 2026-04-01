import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { schemaDefinitions } from '../schemas'
import { getCacheService, CACHE_CONFIGS } from '../services'
import { QueryFilterBuilder, QueryFilter } from '../utils'
import { isPluginActive, optionalAuth } from '../middleware'
import { normalizePublicContentFilter } from './api-content-access-policy'
import apiContentCrudRoutes from './api-content-crud'
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
      version: '0.1.0',
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

    // Cache miss - fetch from database
    c.header('X-Cache-Status', 'MISS')
    c.header('X-Cache-Source', 'database')

    const stmt = db.prepare("SELECT * FROM collections WHERE is_active = 1 AND (source_type IS NULL OR source_type = 'user')")
    const { results } = await stmt.all()

    // Parse schema and format results
    const transformedResults = results.map((row: any) => ({
      ...row,
      schema: row.schema ? JSON.parse(row.schema) : {},
      is_active: row.is_active // Keep as number (1 or 0)
    }))

    const responseData = {
      data: transformedResults,
      meta: addTimingMeta(c, {
        count: results.length,
        timestamp: new Date().toISOString(),
        cache: {
          hit: false,
          source: 'database'
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

    // Handle collection parameter - convert collection name to collection_id
    if (queryParams.collection) {
      const collectionName = queryParams.collection
      const collectionStmt = db.prepare('SELECT id FROM collections WHERE name = ? AND is_active = 1')
      const collectionResult = await collectionStmt.bind(collectionName).first()

      if (collectionResult) {
        // Replace 'collection' param with 'collection_id' for the filter builder
        queryParams.collection_id = (collectionResult as any).id
        delete queryParams.collection
      } else {
        // Collection not found - return empty result
        return c.json({
          data: [],
          meta: addTimingMeta(c, {
            count: 0,
            timestamp: new Date().toISOString(),
            message: `Collection '${collectionName}' not found`
          }, executionStart)
        })
      }
    }

    // Parse filter from query parameters
    const filter: QueryFilter = QueryFilterBuilder.parseFromQuery(queryParams)
    const normalizedFilter = normalizePublicContentFilter(filter, c.get('user')?.role)

    // Set default limit if not provided
    if (!normalizedFilter.limit) {
      normalizedFilter.limit = 50
    }
    normalizedFilter.limit = Math.min(normalizedFilter.limit, 1000) // Max 1000

    // Build SQL query from filter
    const builder = new QueryFilterBuilder()
    const queryResult = builder.build('content', normalizedFilter)

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

    // Transform results to match API spec (camelCase)
    const transformedResults = results.map((row: any) => ({
      id: row.id,
      title: row.title,
      slug: row.slug,
      status: row.status,
      collectionId: row.collection_id,
      data: row.data ? JSON.parse(row.data) : {},
      created_at: row.created_at,
      updated_at: row.updated_at
    }))

    const responseData = {
      data: transformedResults,
      meta: addTimingMeta(c, {
        count: results.length,
        timestamp: new Date().toISOString(),
        filter: normalizedFilter,
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

    // First check if collection exists
    const collectionStmt = db.prepare('SELECT * FROM collections WHERE name = ? AND is_active = 1')
    const collectionResult = await collectionStmt.bind(collection).first()

    if (!collectionResult) {
      return c.json({ error: 'Collection not found' }, 404)
    }

    // Parse filter from query parameters
    const filter: QueryFilter = QueryFilterBuilder.parseFromQuery(queryParams)
    const normalizedFilter = normalizePublicContentFilter(filter, c.get('user')?.role)

    // Add collection_id filter to where clause
    if (!normalizedFilter.where) {
      normalizedFilter.where = { and: [] }
    }

    if (!normalizedFilter.where.and) {
      normalizedFilter.where.and = []
    }

    // Add collection filter
    normalizedFilter.where.and.push({
      field: 'collection_id',
      operator: 'equals',
      value: (collectionResult as any).id
    })

    // Set default limit if not provided
    if (!normalizedFilter.limit) {
      normalizedFilter.limit = 50
    }
    normalizedFilter.limit = Math.min(normalizedFilter.limit, 1000)

    // Build SQL query from filter
    const builder = new QueryFilterBuilder()
    const queryResult = builder.build('content', normalizedFilter)

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

    // Transform results to match API spec (camelCase)
    const transformedResults = results.map((row: any) => ({
      id: row.id,
      title: row.title,
      slug: row.slug,
      status: row.status,
      collectionId: row.collection_id,
      data: row.data ? JSON.parse(row.data) : {},
      created_at: row.created_at,
      updated_at: row.updated_at
    }))

    const responseData = {
      data: transformedResults,
      meta: addTimingMeta(c, {
        collection: {
          ...(collectionResult as any),
          schema: (collectionResult as any).schema ? JSON.parse((collectionResult as any).schema) : {}
        },
        count: results.length,
        timestamp: new Date().toISOString(),
        filter: normalizedFilter,
        cache: {
          hit: false,
          source: 'database'
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

export default apiRoutes
