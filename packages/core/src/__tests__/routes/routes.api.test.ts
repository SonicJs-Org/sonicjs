// @ts-nocheck
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Hono } from 'hono'
// TODO: Skip until routes/api module exists in core package
// import { apiRoutes } from '../routes/api'
// import * as cacheModule from '../plugins/cache'

// Mock the cache service
vi.mock('../plugins/cache', async () => {
  const actual = await vi.importActual('../plugins/cache')
  return {
    ...actual,
    getCacheService: vi.fn(() => ({
      generateKey: vi.fn((prefix: string, key: string) => `${prefix}:${key}`),
      getWithSource: vi.fn().mockResolvedValue({ hit: false, data: null, source: null, ttl: null }),
      set: vi.fn().mockResolvedValue(undefined),
      delete: vi.fn().mockResolvedValue(undefined),
      clear: vi.fn().mockResolvedValue(undefined)
    }))
  }
})

// Mock environment bindings
const createMockEnv = () => ({
  DB: {
    prepare: vi.fn().mockReturnValue({
      bind: vi.fn().mockReturnThis(),
      first: vi.fn(),
      all: vi.fn(),
      run: vi.fn()
    })
  },
  KV: {}
})

describe.skip('API Routes', () => {
  let app: Hono
  let mockEnv: any

  beforeEach(() => {
    vi.clearAllMocks()
    mockEnv = createMockEnv()
    
    // Create new app instance for each test and mount routes at root for testing
    app = new Hono()
    app.route('/', apiRoutes)
  })

  describe('GET /', () => {
    it('should return OpenAPI specification', async () => {
      const res = await app.fetch(new Request('https://test.com/'), mockEnv)
      const data = await res.json() as any
      
      expect(res.status).toBe(200)
      expect(data.openapi).toBe('3.0.0')
      expect(data.info.title).toBe('SonicJS AI API')
      expect(data.info.version).toBe('0.1.0')
      expect(data.paths).toHaveProperty('/api/')
      expect(data.paths).toHaveProperty('/api/health')
      expect(data.paths).toHaveProperty('/api/collections')
    })

    it('should include correct server URL in OpenAPI spec', async () => {
      const res = await app.fetch(new Request('https://example.com/'), mockEnv)
      const data = await res.json() as any
      
      expect(data.servers[0].url).toContain('example.com')
      expect(data.info.contact.url).toContain('example.com/docs')
    })
  })

  describe('GET /health', () => {
    it('should return health status with schemas', async () => {
      const res = await app.fetch(new Request('https://test.com/health'), mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(200)
      expect(data.status).toBe('healthy')
      expect(data.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)
      expect(Array.isArray(data.schemas)).toBe(true)
    })

    it('should include available schema names', async () => {
      const res = await app.fetch(new Request('https://test.com/health'), mockEnv)
      const data = await res.json()
      
      // Check that schemas array contains expected schema names (case-insensitive)
      const schemaNames = data.schemas.map((s: string) => s.toLowerCase())
      expect(schemaNames).toContain('collections')
      expect(schemaNames).toContain('content')
      expect(Array.isArray(data.schemas)).toBe(true)
      expect(data.schemas.length).toBeGreaterThan(0)
    })
  })

  describe('GET /collections', () => {
    it('should return collections successfully', async () => {
      const mockResults = [
        {
          id: '1',
          name: 'blog_post',
          display_name: 'Blog Posts',
          description: 'Blog post content',
          schema: '{"fields": []}',
          is_active: 1,
          created_at: 1640995200000,
          updated_at: 1640995200000
        },
        {
          id: '2', 
          name: 'pages',
          display_name: 'Pages',
          description: 'Static pages',
          schema: '{"fields": [{"name": "title", "type": "text"}]}',
          is_active: 1,
          created_at: 1640995200000,
          updated_at: 1640995200000
        }
      ]

      mockEnv.DB.prepare().all.mockResolvedValue({ results: mockResults })

      const res = await app.fetch(new Request('https://test.com/collections'), mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(200)
      expect(mockEnv.DB.prepare).toHaveBeenCalledWith('SELECT * FROM collections WHERE is_active = 1')
      
      expect(data.data).toHaveLength(2)
      expect(data.data[0].schema).toEqual({ fields: [] })
      expect(data.data[1].schema).toEqual({ fields: [{ name: 'title', type: 'text' }] })
      expect(data.meta.count).toBe(2)
      expect(data.meta.timestamp).toBeDefined()
    })

    it('should handle database errors gracefully', async () => {
      mockEnv.DB.prepare().all.mockRejectedValue(new Error('Database connection failed'))

      const res = await app.fetch(new Request('https://test.com/collections'), mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(500)
      expect(data.error).toBe('Failed to fetch collections')
    })

    it('should handle collections with null schema', async () => {
      const mockResults = [
        {
          id: '1',
          name: 'test_collection',
          display_name: 'Test Collection',
          description: null,
          schema: null,
          is_active: 1,
          created_at: 1640995200000,
          updated_at: 1640995200000
        }
      ]

      mockEnv.DB.prepare().all.mockResolvedValue({ results: mockResults })

      const res = await app.fetch(new Request('https://test.com/collections'), mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(200)
      expect(data.data[0].schema).toEqual({})
    })
  })

  describe('GET /content', () => {
    it('should return content items successfully', async () => {
      const mockResults = [
        {
          id: '1',
          title: 'Test Post',
          slug: 'test-post',
          status: 'published',
          collection_id: 'col1',
          data: '{"content": "Hello world"}',
          created_at: 1640995200000,
          updated_at: 1640995200000
        },
        {
          id: '2',
          title: 'Another Post',
          slug: 'another-post',
          status: 'draft',
          collection_id: 'col1',
          data: '{"content": "Draft content"}',
          created_at: 1640995100000,
          updated_at: 1640995100000
        }
      ]

      mockEnv.DB.prepare().all.mockResolvedValue({ results: mockResults })

      const res = await app.fetch(new Request('https://test.com/content'), mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(200)
      expect(mockEnv.DB.prepare).toHaveBeenCalledWith('SELECT * FROM content LIMIT ?')

      expect(data.data).toHaveLength(2)
      expect(data.data[0].collectionId).toBe('col1') // camelCase transformation
      expect(data.data[0].data).toEqual({ content: 'Hello world' }) // JSON parsing
      expect(data.meta.count).toBe(2)
      expect(data.meta.timestamp).toBeDefined()
    })

    it('should handle database errors gracefully', async () => {
      mockEnv.DB.prepare().all.mockRejectedValue(new Error('Query failed'))

      const res = await app.fetch(new Request('https://test.com/content'), mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(500)
      expect(data.error).toBe('Failed to fetch content')
    })

    it('should handle content with null data field', async () => {
      const mockResults = [
        {
          id: '1',
          title: 'Test Post',
          slug: 'test-post',
          status: 'published',
          collection_id: 'col1',
          data: null,
          created_at: 1640995200000,
          updated_at: 1640995200000
        }
      ]

      mockEnv.DB.prepare().all.mockResolvedValue({ results: mockResults })

      const res = await app.fetch(new Request('https://test.com/content'), mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(200)
      expect(data.data[0].data).toEqual({})
    })
  })

  describe('GET /collections/:collection/content', () => {
    it('should return content for specific collection', async () => {
      const mockCollection = {
        id: 'col1',
        name: 'blog_post',
        display_name: 'Blog Posts',
        schema: '{"fields": [{"name": "title", "type": "text"}]}',
        is_active: 1
      }

      const mockContent = [
        {
          id: '1',
          title: 'Blog Post 1',
          slug: 'blog-post-1',
          status: 'published',
          collection_id: 'col1',
          data: '{"content": "Blog content 1"}',
          created_at: 1640995200000,
          updated_at: 1640995200000
        }
      ]

      // Mock the chained database calls (including isPluginActive middleware call)
      mockEnv.DB.prepare
        .mockReturnValueOnce({
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue(null) // isPluginActive returns null (cache disabled)
          })
        })
        .mockReturnValueOnce({
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue(mockCollection)
          })
        })
        .mockReturnValueOnce({
          bind: vi.fn().mockReturnValue({
            all: vi.fn().mockResolvedValue({ results: mockContent })
          })
        })

      const res = await app.fetch(new Request('https://test.com/collections/blog_post/content'), mockEnv)
      const data = await res.json()

      expect(res.status).toBe(200)
      expect(mockEnv.DB.prepare).toHaveBeenCalledWith('SELECT id FROM plugins WHERE name = ? AND status = ?')
      expect(mockEnv.DB.prepare).toHaveBeenCalledWith('SELECT * FROM collections WHERE name = ? AND is_active = 1')
      expect(mockEnv.DB.prepare).toHaveBeenCalledWith('SELECT * FROM content WHERE (collection_id = ?) LIMIT ?')

      expect(data.data).toHaveLength(1)
      expect(data.data[0].collectionId).toBe('col1')
      expect(data.meta.collection.name).toBe('blog_post')
      expect(data.meta.collection.schema).toEqual({ fields: [{ name: 'title', type: 'text' }] })
    })

    it('should return 404 for non-existent collection', async () => {
      mockEnv.DB.prepare.mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue(null)
        })
      })

      const res = await app.fetch(new Request('https://test.com/collections/nonexistent/content'), mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(404)
      expect(data.error).toBe('Collection not found')
    })

    it('should handle database errors gracefully', async () => {
      mockEnv.DB.prepare.mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockRejectedValue(new Error('Database error'))
        })
      })

      const res = await app.fetch(new Request('https://test.com/collections/blog_post/content'), mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(500)
      expect(data.error).toBe('Failed to fetch content')
    })

    it('should handle collection with null schema', async () => {
      const mockCollection = {
        id: 'col1',
        name: 'test_collection',
        display_name: 'Test Collection',
        schema: null,
        is_active: 1
      }

      const mockContent = [
        {
          id: '1',
          title: 'Test Content',
          slug: 'test-content',
          status: 'published',
          collection_id: 'col1',
          data: '{}',
          created_at: 1640995200000,
          updated_at: 1640995200000
        }
      ]

      mockEnv.DB.prepare
        .mockReturnValueOnce({
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue(null) // isPluginActive returns null (cache disabled)
          })
        })
        .mockReturnValueOnce({
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue(mockCollection)
          })
        })
        .mockReturnValueOnce({
          bind: vi.fn().mockReturnValue({
            all: vi.fn().mockResolvedValue({ results: mockContent })
          })
        })

      const res = await app.fetch(new Request('https://test.com/collections/test_collection/content'), mockEnv)
      const data = await res.json()

      expect(res.status).toBe(200)
      expect(data.meta.collection.schema).toEqual({})
    })
  })

  describe('CORS middleware', () => {
    it('should handle OPTIONS requests for CORS', async () => {
      const req = new Request('https://test.com/health', { 
        method: 'OPTIONS',
        headers: {
          'Origin': 'https://example.com',
          'Access-Control-Request-Method': 'GET'
        }
      })
      
      const res = await app.fetch(req, mockEnv)
      
      expect(res.status).toBe(204) // CORS OPTIONS requests return 204
      expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*')
      
      const allowedMethods = res.headers.get('Access-Control-Allow-Methods')
      expect(allowedMethods).toContain('GET')
      expect(allowedMethods).toContain('POST')
      expect(allowedMethods).toContain('PUT')
      expect(allowedMethods).toContain('DELETE')
    })

    it('should include CORS headers on regular requests', async () => {
      const res = await app.fetch(new Request('https://test.com/health'), mockEnv)
      
      expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*')
    })
  })
})