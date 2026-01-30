/**
 * Collection Sync Service Tests
 */

import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest'
import {
  syncCollections,
  syncCollection,
  isCollectionManaged,
  getManagedCollections,
  cleanupRemovedCollections,
  fullCollectionSync
} from './collection-sync'
import type { CollectionConfig } from '../types/collection-config'

// Mock the collection-loader module
vi.mock('./collection-loader', () => ({
  loadCollectionConfigs: vi.fn(),
  validateCollectionConfig: vi.fn()
}))

import { loadCollectionConfigs, validateCollectionConfig } from './collection-loader'

// Mock D1Database
function createMockDb() {
  const mockPrepare = vi.fn()
  const mockBind = vi.fn()
  const mockFirst = vi.fn()
  const mockAll = vi.fn()
  const mockRun = vi.fn()

  const chainable = {
    bind: mockBind.mockReturnThis(),
    first: mockFirst,
    all: mockAll,
    run: mockRun
  }

  mockPrepare.mockReturnValue(chainable)

  return {
    prepare: mockPrepare,
    _mocks: {
      prepare: mockPrepare,
      bind: mockBind,
      first: mockFirst,
      all: mockAll,
      run: mockRun
    }
  }
}

// Sample collection config for testing
function createTestConfig(overrides: Partial<CollectionConfig> = {}): CollectionConfig {
  return {
    name: 'test-collection',
    displayName: 'Test Collection',
    description: 'A test collection',
    schema: {
      fields: [
        { name: 'title', type: 'text', label: 'Title', required: true }
      ]
    },
    isActive: true,
    managed: true,
    ...overrides
  }
}

describe('syncCollection', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
    // Default to valid validation
    ;(validateCollectionConfig as Mock).mockReturnValue({ valid: true, errors: [] })
  })

  it('should return error when validation fails', async () => {
    ;(validateCollectionConfig as Mock).mockReturnValue({
      valid: false,
      errors: ['Missing required field: name']
    })

    const config = createTestConfig()
    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('error')
    expect(result.error).toContain('Validation failed')
    expect(result.error).toContain('Missing required field: name')
  })

  it('should create new collection when it does not exist', async () => {
    mockDb._mocks.first.mockResolvedValue(null) // No existing collection
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const config = createTestConfig()
    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('created')
    expect(result.name).toBe('test-collection')
    expect(result.message).toContain('Created collection')
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO collections'))
  })

  it('should return unchanged when collection exists and matches config', async () => {
    const config = createTestConfig()
    // The code does JSON.stringify(existing.schema) so we need to return the object, not a string
    mockDb._mocks.first.mockResolvedValue({
      id: 'col-test-123',
      name: 'test-collection',
      display_name: 'Test Collection',
      description: 'A test collection',
      schema: config.schema, // Object, not string - will be stringified by the code
      is_active: 1,
      managed: 1
    })

    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('unchanged')
    expect(result.message).toContain('is up to date')
  })

  it('should update collection when schema differs', async () => {
    const config = createTestConfig()

    mockDb._mocks.first.mockResolvedValue({
      id: 'col-test-123',
      name: 'test-collection',
      display_name: 'Test Collection',
      description: 'A test collection',
      schema: JSON.stringify({ fields: [] }), // Different schema
      is_active: 1,
      managed: 1
    })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('updated')
    expect(result.message).toContain('Updated collection')
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith(expect.stringContaining('UPDATE collections'))
  })

  it('should update collection when displayName differs', async () => {
    const config = createTestConfig({ displayName: 'New Display Name' })

    mockDb._mocks.first.mockResolvedValue({
      id: 'col-test-123',
      name: 'test-collection',
      display_name: 'Old Display Name',
      description: 'A test collection',
      schema: JSON.stringify(config.schema),
      is_active: 1,
      managed: 1
    })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('updated')
  })

  it('should update collection when description differs', async () => {
    const config = createTestConfig({ description: 'New description' })

    mockDb._mocks.first.mockResolvedValue({
      id: 'col-test-123',
      name: 'test-collection',
      display_name: 'Test Collection',
      description: 'Old description',
      schema: JSON.stringify(config.schema),
      is_active: 1,
      managed: 1
    })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('updated')
  })

  it('should update collection when isActive changes', async () => {
    const config = createTestConfig({ isActive: false })

    mockDb._mocks.first.mockResolvedValue({
      id: 'col-test-123',
      name: 'test-collection',
      display_name: 'Test Collection',
      description: 'A test collection',
      schema: JSON.stringify(config.schema),
      is_active: 1,
      managed: 1
    })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('updated')
  })

  it('should update collection when managed changes', async () => {
    const config = createTestConfig({ managed: false })

    mockDb._mocks.first.mockResolvedValue({
      id: 'col-test-123',
      name: 'test-collection',
      display_name: 'Test Collection',
      description: 'A test collection',
      schema: JSON.stringify(config.schema),
      is_active: 1,
      managed: 1
    })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('updated')
  })

  it('should handle null description correctly', async () => {
    const config = createTestConfig({ description: undefined })

    mockDb._mocks.first.mockResolvedValue({
      id: 'col-test-123',
      name: 'test-collection',
      display_name: 'Test Collection',
      description: null,
      schema: config.schema, // Object, not string
      is_active: 1,
      managed: 1
    })

    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('unchanged')
  })

  it('should return error when database operation fails', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockDb._mocks.first.mockRejectedValue(new Error('Database connection failed'))

    const config = createTestConfig()
    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('error')
    expect(result.error).toBe('Database connection failed')
    consoleSpy.mockRestore()
  })

  it('should handle non-Error exceptions', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockDb._mocks.first.mockRejectedValue('String error')

    const config = createTestConfig()
    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('error')
    expect(result.error).toBe('Unknown error')
    consoleSpy.mockRestore()
  })

  it('should default isActive to true when undefined', async () => {
    mockDb._mocks.first.mockResolvedValue(null)
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const config = createTestConfig()
    delete (config as any).isActive

    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('created')
    // Verify isActive was set to 1 (true)
    expect(mockDb._mocks.bind).toHaveBeenCalledWith(
      expect.any(String), // id
      'test-collection',
      'Test Collection',
      'A test collection',
      expect.any(String), // schema
      1, // isActive defaults to true
      1, // managed
      expect.any(Number),
      expect.any(Number)
    )
  })

  it('should default managed to true when undefined', async () => {
    mockDb._mocks.first.mockResolvedValue(null)
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const config = createTestConfig()
    delete (config as any).managed

    const result = await syncCollection(mockDb as any, config)

    expect(result.status).toBe('created')
  })
})

describe('syncCollections', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
    ;(validateCollectionConfig as Mock).mockReturnValue({ valid: true, errors: [] })
  })

  it('should return empty results when no configs found', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    ;(loadCollectionConfigs as Mock).mockResolvedValue([])

    const results = await syncCollections(mockDb as any)

    expect(results).toEqual([])
    expect(consoleSpy).toHaveBeenCalledWith('⚠️  No collection configurations found')
    consoleSpy.mockRestore()
  })

  it('should sync all configs and return results', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    ;(loadCollectionConfigs as Mock).mockResolvedValue([
      createTestConfig({ name: 'collection1' }),
      createTestConfig({ name: 'collection2' })
    ])
    mockDb._mocks.first.mockResolvedValue(null)
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const results = await syncCollections(mockDb as any)

    expect(results).toHaveLength(2)
    expect(results[0].status).toBe('created')
    expect(results[1].status).toBe('created')
    consoleSpy.mockRestore()
  })

  it('should log summary with correct counts', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const testConfig = createTestConfig({ name: 'existing-collection' })
    ;(loadCollectionConfigs as Mock).mockResolvedValue([
      createTestConfig({ name: 'new-collection' }),
      testConfig
    ])

    // First call returns null (create), second returns existing with matching config (unchanged)
    mockDb._mocks.first
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({
        id: 'col-123',
        name: 'existing-collection',
        display_name: 'Test Collection',
        description: 'A test collection',
        schema: testConfig.schema, // Use same schema object
        is_active: 1,
        managed: 1
      })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    await syncCollections(mockDb as any)

    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('1 created'))
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('1 unchanged'))
    consoleSpy.mockRestore()
  })
})

describe('isCollectionManaged', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
  })

  it('should return true when collection is managed', async () => {
    mockDb._mocks.first.mockResolvedValue({ managed: 1 })

    const result = await isCollectionManaged(mockDb as any, 'my-collection')

    expect(result).toBe(true)
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith('SELECT managed FROM collections WHERE name = ?')
    expect(mockDb._mocks.bind).toHaveBeenCalledWith('my-collection')
  })

  it('should return false when collection is not managed', async () => {
    mockDb._mocks.first.mockResolvedValue({ managed: 0 })

    const result = await isCollectionManaged(mockDb as any, 'my-collection')

    expect(result).toBe(false)
  })

  it('should return false when collection does not exist', async () => {
    mockDb._mocks.first.mockResolvedValue(null)

    const result = await isCollectionManaged(mockDb as any, 'nonexistent')

    expect(result).toBe(false)
  })

  it('should return false and log error on database error', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockDb._mocks.first.mockRejectedValue(new Error('DB error'))

    const result = await isCollectionManaged(mockDb as any, 'my-collection')

    expect(result).toBe(false)
    expect(consoleSpy).toHaveBeenCalledWith(
      'Error checking if collection is managed:',
      expect.any(Error)
    )
    consoleSpy.mockRestore()
  })
})

describe('getManagedCollections', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
  })

  it('should return array of managed collection names', async () => {
    mockDb._mocks.all.mockResolvedValue({
      results: [
        { name: 'collection1' },
        { name: 'collection2' },
        { name: 'collection3' }
      ]
    })

    const result = await getManagedCollections(mockDb as any)

    expect(result).toEqual(['collection1', 'collection2', 'collection3'])
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith("SELECT name FROM collections WHERE managed = 1 AND (source_type IS NULL OR source_type = 'user')")
  })

  it('should return empty array when no managed collections', async () => {
    mockDb._mocks.all.mockResolvedValue({ results: [] })

    const result = await getManagedCollections(mockDb as any)

    expect(result).toEqual([])
  })

  it('should return empty array when results is null', async () => {
    mockDb._mocks.all.mockResolvedValue({ results: null })

    const result = await getManagedCollections(mockDb as any)

    expect(result).toEqual([])
  })

  it('should return empty array and log error on database error', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockDb._mocks.all.mockRejectedValue(new Error('DB error'))

    const result = await getManagedCollections(mockDb as any)

    expect(result).toEqual([])
    expect(consoleSpy).toHaveBeenCalledWith(
      'Error getting managed collections:',
      expect.any(Error)
    )
    consoleSpy.mockRestore()
  })
})

describe('cleanupRemovedCollections', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
  })

  it('should deactivate collections not in configs', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    ;(loadCollectionConfigs as Mock).mockResolvedValue([
      createTestConfig({ name: 'active-collection' })
    ])

    // getManagedCollections call
    mockDb._mocks.all.mockResolvedValue({
      results: [
        { name: 'active-collection' },
        { name: 'removed-collection' }
      ]
    })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await cleanupRemovedCollections(mockDb as any)

    expect(result).toEqual(['removed-collection'])
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith(expect.stringContaining('UPDATE collections'))
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith(expect.stringContaining('is_active = 0'))
    consoleSpy.mockRestore()
  })

  it('should return empty array when all collections have configs', async () => {
    ;(loadCollectionConfigs as Mock).mockResolvedValue([
      createTestConfig({ name: 'collection1' }),
      createTestConfig({ name: 'collection2' })
    ])

    mockDb._mocks.all.mockResolvedValue({
      results: [
        { name: 'collection1' },
        { name: 'collection2' }
      ]
    })

    const result = await cleanupRemovedCollections(mockDb as any)

    expect(result).toEqual([])
  })

  it('should return empty array when no managed collections', async () => {
    ;(loadCollectionConfigs as Mock).mockResolvedValue([
      createTestConfig({ name: 'collection1' })
    ])

    mockDb._mocks.all.mockResolvedValue({ results: [] })

    const result = await cleanupRemovedCollections(mockDb as any)

    expect(result).toEqual([])
  })

  it('should return empty array and log error on database error', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    ;(loadCollectionConfigs as Mock).mockRejectedValue(new Error('Load error'))

    const result = await cleanupRemovedCollections(mockDb as any)

    expect(result).toEqual([])
    expect(consoleSpy).toHaveBeenCalledWith(
      'Error cleaning up removed collections:',
      expect.any(Error)
    )
    consoleSpy.mockRestore()
  })
})

describe('fullCollectionSync', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
    ;(validateCollectionConfig as Mock).mockReturnValue({ valid: true, errors: [] })
  })

  it('should sync collections and cleanup removed ones', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    ;(loadCollectionConfigs as Mock).mockResolvedValue([
      createTestConfig({ name: 'active-collection' })
    ])

    // syncCollections first call
    mockDb._mocks.first.mockResolvedValue(null)
    mockDb._mocks.run.mockResolvedValue({ success: true })

    // cleanupRemovedCollections getManagedCollections call
    mockDb._mocks.all.mockResolvedValue({
      results: [
        { name: 'active-collection' },
        { name: 'old-collection' }
      ]
    })

    const { results, removed } = await fullCollectionSync(mockDb as any)

    expect(results).toHaveLength(1)
    expect(results[0].status).toBe('created')
    expect(removed).toEqual(['old-collection'])
    consoleSpy.mockRestore()
  })

  it('should return empty arrays when no configs', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    ;(loadCollectionConfigs as Mock).mockResolvedValue([])
    mockDb._mocks.all.mockResolvedValue({ results: [] })

    const { results, removed } = await fullCollectionSync(mockDb as any)

    expect(results).toEqual([])
    expect(removed).toEqual([])
    consoleSpy.mockRestore()
  })
})
