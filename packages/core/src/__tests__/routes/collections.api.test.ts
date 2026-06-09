import { describe, it, expect, beforeEach, vi } from 'vitest'

// Mock database operations for API testing
const mockDb = {
  prepare: vi.fn().mockReturnValue({
    bind: vi.fn().mockReturnValue({
      run: vi.fn().mockResolvedValue({}),
      all: vi.fn().mockResolvedValue([]),
      first: vi.fn().mockResolvedValue(null)
    }),
    run: vi.fn().mockResolvedValue({}),
    all: vi.fn().mockResolvedValue([]),
    first: vi.fn().mockResolvedValue(null)
  })
}

// Mock environment (used by some test scenarios)
const mockEnv = {
  DB: mockDb,
  CLOUDFLARE_API_TOKEN: 'test-token'
}

// Mock API functions
const collectionsAPI = {
  async getCollections(db: any) {
    try {
      const collections = await db.prepare(`
        SELECT id, name, display_name as displayName, description, created_at as createdAt
        FROM collections 
        WHERE is_active = 1 
        ORDER BY created_at DESC
      `).all()

      return {
        status: 200,
        data: {
          collections: collections.results || [],
          total: collections.results?.length || 0
        }
      }
    } catch (error) {
      return {
        status: 500,
        data: { error: 'Failed to fetch collections' }
      }
    }
  },

  async getCollectionContent(db: any, collectionName: string) {
    try {
      // First, find the collection
      const collection = await db.prepare(`
        SELECT id FROM collections 
        WHERE name = ? AND is_active = 1
      `).bind(collectionName).first()

      if (!collection) {
        return {
          status: 404,
          data: { error: 'Collection not found' }
        }
      }

      // Get content for this collection
      const content = await db.prepare(`
        SELECT c.id, c.title, c.slug, c.status, c.published_at as publishedAt,
               u.username as author, c.created_at as createdAt
        FROM content c
        LEFT JOIN users u ON c.author_id = u.id
        WHERE c.collection_id = ?
        ORDER BY c.created_at DESC
      `).bind(collection.id).all()

      return {
        status: 200,
        data: {
          collection: collectionName,
          content: content.results || [],
          total: content.results?.length || 0
        }
      }
    } catch (error) {
      return {
        status: 500,
        data: { error: 'Failed to fetch collection content' }
      }
    }
  },

  async createCollection(db: any, data: any) {
    try {
      const { name, displayName, description } = data

      // Validate required fields
      if (!name || !displayName) {
        return {
          status: 400,
          data: { error: 'Name and display name are required' }
        }
      }

      // Validate name format
      if (!/^[a-z0-9_]+$/.test(name)) {
        return {
          status: 400,
          data: { error: 'Collection name must contain only lowercase letters, numbers, and underscores' }
        }
      }

      // Check if collection already exists
      const existing = await db.prepare(`
        SELECT id FROM collections WHERE name = ?
      `).bind(name).first()

      if (existing) {
        return {
          status: 409,
          data: { error: 'Collection with this name already exists' }
        }
      }

      // Create the collection
      const collectionId = `collection_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`
      const now = Date.now()
      const defaultSchema = JSON.stringify({
        type: 'object',
        properties: {
          title: { type: 'string', title: 'Title', required: true },
          content: { type: 'string', title: 'Content', format: 'richtext' }
        },
        required: ['title']
      })

      await db.prepare(`
        INSERT INTO collections (id, name, display_name, description, schema, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
      `).bind(collectionId, name, displayName, description || null, defaultSchema, now, now).run()

      return {
        status: 201,
        data: {
          id: collectionId,
          name,
          displayName,
          description,
          message: 'Collection created successfully'
        }
      }
    } catch (error) {
      return {
        status: 500,
        data: { error: 'Failed to create collection' }
      }
    }
  },

  async updateCollection(db: any, id: string, data: any) {
    try {
      const { displayName, description, schema } = data

      if (!displayName) {
        return {
          status: 400,
          data: { error: 'Display name is required' }
        }
      }

      // Check if collection exists
      const existing = await db.prepare(`
        SELECT id FROM collections WHERE id = ?
      `).bind(id).first()

      if (!existing) {
        return {
          status: 404,
          data: { error: 'Collection not found' }
        }
      }

      // Update the collection
      const now = Date.now()
      await db.prepare(`
        UPDATE collections 
        SET display_name = ?, description = ?, schema = ?, updated_at = ?
        WHERE id = ?
      `).bind(
        displayName, 
        description || null, 
        schema ? JSON.stringify(schema) : null, 
        now, 
        id
      ).run()

      return {
        status: 200,
        data: {
          id,
          displayName,
          description,
          message: 'Collection updated successfully'
        }
      }
    } catch (error) {
      return {
        status: 500,
        data: { error: 'Failed to update collection' }
      }
    }
  },

  async deleteCollection(db: any, id: string) {
    try {
      // Check if collection exists
      const existing = await db.prepare(`
        SELECT id FROM collections WHERE id = ?
      `).bind(id).first()

      if (!existing) {
        return {
          status: 404,
          data: { error: 'Collection not found' }
        }
      }

      // Check if collection has content
      const contentCount = await db.prepare(`
        SELECT COUNT(*) as count FROM content WHERE collection_id = ?
      `).bind(id).first()

      if (contentCount && contentCount.count > 0) {
        return {
          status: 409,
          data: { error: 'Cannot delete collection that contains content' }
        }
      }

      // Delete the collection
      await db.prepare(`
        DELETE FROM collections WHERE id = ?
      `).bind(id).run()

      return {
        status: 200,
        data: { message: 'Collection deleted successfully' }
      }
    } catch (error) {
      return {
        status: 500,
        data: { error: 'Failed to delete collection' }
      }
    }
  }
}

describe('Collections API Logic', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    
    // Create a fresh mock for each test
    const preparedStatementMock = {
      bind: vi.fn().mockReturnThis(),
      run: vi.fn().mockResolvedValue({}),
      all: vi.fn().mockResolvedValue({ results: [] }),
      first: vi.fn().mockResolvedValue(null)
    }
    
    mockDb.prepare.mockReturnValue(preparedStatementMock)
  })

  describe('Get Collections', () => {
    it('should return list of active collections', async () => {
      const mockCollections = [
        {
          id: 'collection-1',
          name: 'blog_post',
          displayName: 'Blog Posts',
          description: 'Blog post collection',
          createdAt: '2023-01-01T00:00:00Z'
        },
        {
          id: 'collection-2',
          name: 'pages',
          displayName: 'Pages',
          description: 'Static pages collection',
          createdAt: '2023-01-02T00:00:00Z'
        }
      ]

      mockDb.prepare().all.mockResolvedValueOnce({
        results: mockCollections
      })

      const result = await collectionsAPI.getCollections(mockDb)

      expect(result.status).toBe(200)
      expect(result.data.collections).toEqual(mockCollections)
      expect(result.data.total).toBe(2)
    })

    it('should return empty array when no collections exist', async () => {
      mockDb.prepare().all.mockResolvedValueOnce({
        results: []
      })

      const result = await collectionsAPI.getCollections(mockDb)

      expect(result.status).toBe(200)
      expect(result.data.collections).toEqual([])
      expect(result.data.total).toBe(0)
    })

    it('should handle database errors', async () => {
      mockDb.prepare().all.mockRejectedValueOnce(new Error('Database error'))

      const result = await collectionsAPI.getCollections(mockDb)

      expect(result.status).toBe(500)
      expect(result.data.error).toBe('Failed to fetch collections')
    })
  })

  describe('Get Collection Content', () => {
    it('should return content for existing collection', async () => {
      const mockCollection = { id: 'collection-1' }
      const mockContent = [
        {
          id: 'content-1',
          title: 'Test Post',
          slug: 'test-post',
          status: 'published',
          author: 'admin',
          createdAt: '2023-01-01T00:00:00Z'
        }
      ]

      // Mock the two separate prepare calls
      const firstPrepare = {
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue(mockCollection)
      }
      const secondPrepare = {
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: mockContent })
      }

      mockDb.prepare
        .mockReturnValueOnce(firstPrepare)
        .mockReturnValueOnce(secondPrepare)

      const result = await collectionsAPI.getCollectionContent(mockDb, 'blog_post')

      expect(result.status).toBe(200)
      expect(result.data.collection).toBe('blog_post')
      expect(result.data.content).toEqual(mockContent)
      expect(result.data.total).toBe(1)
    })

    it('should return 404 for non-existent collection', async () => {
      mockDb.prepare().first.mockResolvedValueOnce(null)

      const result = await collectionsAPI.getCollectionContent(mockDb, 'non_existent')

      expect(result.status).toBe(404)
      expect(result.data.error).toBe('Collection not found')
    })
  })

  describe('Create Collection', () => {
    it('should create new collection with valid data', async () => {
      const collectionData = {
        name: 'test_collection',
        displayName: 'Test Collection',
        description: 'A test collection'
      }

      mockDb.prepare().first
        .mockResolvedValueOnce(null) // no existing collection
        .mockResolvedValueOnce(null) // Reset for second prepare call
      mockDb.prepare().run.mockResolvedValueOnce({}) // successful insert

      const result = await collectionsAPI.createCollection(mockDb, collectionData)

      expect(result.status).toBe(201)
      expect(result.data.name).toBe(collectionData.name)
      expect(result.data.displayName).toBe(collectionData.displayName)
      expect(result.data.description).toBe(collectionData.description)
      expect(result.data.message).toBe('Collection created successfully')
      expect(result.data.id).toMatch(/^collection_\d+_[a-z0-9]+$/)
    })

    it('should reject collection with missing required fields', async () => {
      const invalidData = {
        displayName: 'Test Collection'
        // missing name
      }

      const result = await collectionsAPI.createCollection(mockDb, invalidData)

      expect(result.status).toBe(400)
      expect(result.data.error).toBe('Name and display name are required')
    })

    it('should reject collection with invalid name format', async () => {
      const invalidData = {
        name: 'Invalid Collection Name',
        displayName: 'Invalid Collection'
      }

      const result = await collectionsAPI.createCollection(mockDb, invalidData)

      expect(result.status).toBe(400)
      expect(result.data.error).toBe('Collection name must contain only lowercase letters, numbers, and underscores')
    })

    it('should reject duplicate collection names', async () => {
      const collectionData = {
        name: 'existing_collection',
        displayName: 'Existing Collection'
      }

      const prepareWithExisting = {
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ id: 'existing-id' })
      }

      mockDb.prepare.mockReturnValueOnce(prepareWithExisting)

      const result = await collectionsAPI.createCollection(mockDb, collectionData)

      expect(result.status).toBe(409)
      expect(result.data.error).toBe('Collection with this name already exists')
    })
  })

  describe('Update Collection', () => {
    it('should update existing collection', async () => {
      const updateData = {
        displayName: 'Updated Collection Name',
        description: 'Updated description'
      }

      const checkExistsPrepare = {
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ id: 'collection-1' })
      }
      const updatePrepare = {
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({})
      }

      mockDb.prepare
        .mockReturnValueOnce(checkExistsPrepare)
        .mockReturnValueOnce(updatePrepare)

      const result = await collectionsAPI.updateCollection(mockDb, 'collection-1', updateData)

      expect(result.status).toBe(200)
      expect(result.data.displayName).toBe(updateData.displayName)
      expect(result.data.description).toBe(updateData.description)
      expect(result.data.message).toBe('Collection updated successfully')
    })

    it('should return 404 for non-existent collection', async () => {
      const updateData = {
        displayName: 'Updated Name'
      }

      mockDb.prepare().first.mockResolvedValueOnce(null) // collection not found

      const result = await collectionsAPI.updateCollection(mockDb, 'non-existent', updateData)

      expect(result.status).toBe(404)
      expect(result.data.error).toBe('Collection not found')
    })
  })

  describe('Delete Collection', () => {
    it('should delete empty collection', async () => {
      const checkExistsPrepare = {
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ id: 'collection-1' })
      }
      const checkContentPrepare = {
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ count: 0 })
      }
      const deletePrepare = {
        bind: vi.fn().mockReturnThis(),
        run: vi.fn().mockResolvedValue({})
      }

      mockDb.prepare
        .mockReturnValueOnce(checkExistsPrepare)
        .mockReturnValueOnce(checkContentPrepare)
        .mockReturnValueOnce(deletePrepare)

      const result = await collectionsAPI.deleteCollection(mockDb, 'collection-1')

      expect(result.status).toBe(200)
      expect(result.data.message).toBe('Collection deleted successfully')
    })

    it('should reject deletion of collection with content', async () => {
      const checkExistsPrepare = {
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ id: 'collection-1' })
      }
      const checkContentPrepare = {
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue({ count: 5 })
      }

      mockDb.prepare
        .mockReturnValueOnce(checkExistsPrepare)
        .mockReturnValueOnce(checkContentPrepare)

      const result = await collectionsAPI.deleteCollection(mockDb, 'collection-1')

      expect(result.status).toBe(409)
      expect(result.data.error).toBe('Cannot delete collection that contains content')
    })

    it('should return 404 for non-existent collection', async () => {
      mockDb.prepare().first.mockResolvedValueOnce(null) // collection not found

      const result = await collectionsAPI.deleteCollection(mockDb, 'non-existent')

      expect(result.status).toBe(404)
      expect(result.data.error).toBe('Collection not found')
    })
  })

  describe('Error Handling', () => {
    it('should handle database connection errors gracefully', async () => {
      mockDb.prepare.mockImplementationOnce(() => {
        throw new Error('Database connection failed')
      })

      const result = await collectionsAPI.getCollections(mockDb)

      expect(result.status).toBe(500)
      expect(result.data.error).toBe('Failed to fetch collections')
    })

    it('should prevent SQL injection attempts', async () => {
      const maliciousData = {
        name: "test'; DROP TABLE collections; --",
        displayName: 'Malicious Collection'
      }

      const result = await collectionsAPI.createCollection(mockDb, maliciousData)

      expect(result.status).toBe(400)
      expect(result.data.error).toBe('Collection name must contain only lowercase letters, numbers, and underscores')
    })
  })
})