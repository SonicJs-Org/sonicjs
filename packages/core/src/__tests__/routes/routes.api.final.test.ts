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

describe.skip('API Routes - Final Working Tests', () => {
  let mockEnv: any

  beforeEach(() => {
    vi.clearAllMocks()
    mockEnv = {
      DB: {
        prepare: vi.fn(),
        exec: vi.fn(),
      },
      KV: {}
    }
  })

  describe('Working Tests Using Hono.testApp Pattern', () => {
    it('should return OpenAPI specification', async () => {
      const app = new Hono<{ Bindings: typeof mockEnv }>()
      app.route('/', apiRoutes)
      
      const req = new Request('https://test.com/')
      const res = await app.fetch(req, mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(200)
      expect(data.openapi).toBe('3.0.0')
      expect(data.info.title).toBe('SonicJS AI API')
    })

    it('should return health status', async () => {
      const app = new Hono<{ Bindings: typeof mockEnv }>()
      app.route('/', apiRoutes)
      
      const req = new Request('https://test.com/health')
      const res = await app.fetch(req, mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(200)
      expect(data.status).toBe('healthy')
      expect(Array.isArray(data.schemas)).toBe(true)
    })

    it('should return collections with database mocking', async () => {
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
        }
      ]

      const mockPrepare = vi.fn().mockReturnValue({
        all: vi.fn().mockResolvedValue({ results: mockResults })
      })
      
      const testEnv = {
        ...mockEnv,
        DB: { prepare: mockPrepare }
      }

      const app = new Hono<{ Bindings: typeof testEnv }>()
      app.route('/', apiRoutes)

      const req = new Request('https://test.com/collections')
      const res = await app.fetch(req, testEnv)
      const data = await res.json()
      
      expect(res.status).toBe(200)
      expect(mockPrepare).toHaveBeenCalledWith('SELECT * FROM collections WHERE is_active = 1')
      expect(data.data).toHaveLength(1)
      expect(data.data[0].schema).toEqual({ fields: [] })
    })

    it('should handle database errors', async () => {
      const mockPrepare = vi.fn().mockReturnValue({
        all: vi.fn().mockRejectedValue(new Error('Database error'))
      })
      
      const testEnv = {
        ...mockEnv,
        DB: { prepare: mockPrepare }
      }

      const app = new Hono<{ Bindings: typeof testEnv }>()
      app.route('/', apiRoutes)

      const req = new Request('https://test.com/collections')
      const res = await app.fetch(req, testEnv)
      const data = await res.json()
      
      expect(res.status).toBe(500)
      expect(data.error).toBe('Failed to fetch collections')
    })

    it('should handle content endpoint', async () => {
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
        }
      ]

      const mockPrepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: mockResults })
      })
      
      const testEnv = {
        ...mockEnv,
        DB: { prepare: mockPrepare }
      }

      const app = new Hono<{ Bindings: typeof testEnv }>()
      app.route('/', apiRoutes)

      const req = new Request('https://test.com/content')
      const res = await app.fetch(req, testEnv)
      const data = await res.json()
      
      expect(res.status).toBe(200)
      expect(data.data).toHaveLength(1)
      expect(data.data[0].collectionId).toBe('col1')
      expect(data.data[0].data).toEqual({ content: 'Hello world' })
    })

    it('should handle collection-specific content with D1 chaining', async () => {
      const mockCollection = {
        id: 'col1',
        name: 'blog_post',
        display_name: 'Blog Posts',
        schema: '{"fields": []}',
        is_active: 1
      }

      const mockContent = [
        {
          id: '1',
          title: 'Blog Post 1',
          slug: 'blog-post-1',
          status: 'published',
          collection_id: 'col1',
          data: '{"content": "Blog content"}',
          created_at: 1640995200000,
          updated_at: 1640995200000
        }
      ]

      // Mock D1 chaining pattern (including isPluginActive middleware call)
      const mockPrepare = vi.fn()
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

      const testEnv = {
        ...mockEnv,
        DB: { prepare: mockPrepare }
      }

      const app = new Hono<{ Bindings: typeof testEnv }>()
      app.route('/', apiRoutes)

      const req = new Request('https://test.com/collections/blog_post/content')
      const res = await app.fetch(req, testEnv)
      const data = await res.json()

      expect(res.status).toBe(200)
      expect(data.data).toHaveLength(1)
      expect(data.meta.collection.name).toBe('blog_post')
    })

    it('should return 404 for non-existent collection', async () => {
      const mockPrepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue(null)
        })
      })
      
      const testEnv = {
        ...mockEnv,
        DB: { prepare: mockPrepare }
      }

      const app = new Hono<{ Bindings: typeof testEnv }>()
      app.route('/', apiRoutes)

      const req = new Request('https://test.com/collections/nonexistent/content')
      const res = await app.fetch(req, testEnv)
      const data = await res.json()
      
      expect(res.status).toBe(404)
      expect(data.error).toBe('Collection not found')
    })
  })

  describe('Testing with /api prefix (like production)', () => {
    it('should work when mounted at /api', async () => {
      const app = new Hono<{ Bindings: typeof mockEnv }>()
      app.route('/api', apiRoutes)
      
      const req = new Request('https://test.com/api/health')
      const res = await app.fetch(req, mockEnv)
      const data = await res.json()
      
      expect(res.status).toBe(200)
      expect(data.status).toBe('healthy')
    })

    it('should serve OpenAPI spec at /api/', async () => {
      const app = new Hono<{ Bindings: typeof mockEnv }>()
      app.route('/api', apiRoutes)
      
      const req = new Request('https://test.com/api')
      const res = await app.fetch(req, mockEnv)
      
      expect(res.status).toBe(200)
      
      const responseText = await res.text()
      let data
      try {
        data = JSON.parse(responseText)
      } catch (error) {
        console.error('Response is not valid JSON:', responseText)
        throw error
      }
      
      expect(data.openapi).toBe('3.0.0')
    })

    it('should handle collections at /api/collections', async () => {
      const mockResults = [{ id: '1', name: 'test', is_active: 1, schema: null }]
      const mockPrepare = vi.fn().mockReturnValue({
        all: vi.fn().mockResolvedValue({ results: mockResults })
      })
      
      const testEnv = { ...mockEnv, DB: { prepare: mockPrepare } }
      
      const app = new Hono<{ Bindings: typeof testEnv }>()
      app.route('/api', apiRoutes)
      
      const req = new Request('https://test.com/api/collections')
      const res = await app.fetch(req, testEnv)
      const data = await res.json()
      
      expect(res.status).toBe(200)
      expect(data.data).toHaveLength(1)
    })
  })

  describe('CORS middleware', () => {
    it('should handle OPTIONS requests', async () => {
      const app = new Hono<{ Bindings: typeof mockEnv }>()
      app.route('/', apiRoutes)
      
      const req = new Request('https://test.com/health', { 
        method: 'OPTIONS',
        headers: {
          'Origin': 'https://example.com',
          'Access-Control-Request-Method': 'GET'
        }
      })
      const res = await app.fetch(req, mockEnv)
      
      expect(res.status).toBe(204)
      expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*')
    })
  })
})