/**
 * Plugin Middleware Tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  isPluginActive,
  requireActivePlugin,
  requireActivePlugins,
  getActivePlugins
} from './plugin-middleware'

// Mock D1Database
function createMockDb() {
  const mockPrepare = vi.fn()
  const mockBind = vi.fn()
  const mockFirst = vi.fn()
  const mockAll = vi.fn()

  const chainable = {
    bind: mockBind.mockReturnThis(),
    first: mockFirst,
    all: mockAll
  }

  mockPrepare.mockReturnValue(chainable)

  return {
    prepare: mockPrepare,
    _mocks: {
      prepare: mockPrepare,
      bind: mockBind,
      first: mockFirst,
      all: mockAll
    }
  }
}

describe('isPluginActive', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
  })

  it('should return true when plugin status is active', async () => {
    mockDb._mocks.first.mockResolvedValue({ status: 'active' })

    const result = await isPluginActive(mockDb as any, 'my-plugin')

    expect(result).toBe(true)
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith(
      `SELECT json_extract(data, '$.status') as status FROM documents
         WHERE slug = ? AND type_id = 'plugin' AND tenant_id = 'default'
           AND is_current_draft = 1 AND deleted_at IS NULL`
    )
    expect(mockDb._mocks.bind).toHaveBeenCalledWith('my-plugin')
  })

  it('should return false when plugin status is inactive', async () => {
    mockDb._mocks.first.mockResolvedValue({ status: 'inactive' })

    const result = await isPluginActive(mockDb as any, 'my-plugin')

    expect(result).toBe(false)
  })

  it('should return false when plugin status is disabled', async () => {
    mockDb._mocks.first.mockResolvedValue({ status: 'disabled' })

    const result = await isPluginActive(mockDb as any, 'my-plugin')

    expect(result).toBe(false)
  })

  it('should return false when plugin does not exist', async () => {
    mockDb._mocks.first.mockResolvedValue(null)

    const result = await isPluginActive(mockDb as any, 'nonexistent-plugin')

    expect(result).toBe(false)
  })

  it('should return false when result has no status property', async () => {
    mockDb._mocks.first.mockResolvedValue({})

    const result = await isPluginActive(mockDb as any, 'my-plugin')

    expect(result).toBe(false)
  })

  it('should return false and log error on database error', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockDb._mocks.first.mockRejectedValue(new Error('DB error'))

    const result = await isPluginActive(mockDb as any, 'my-plugin')

    expect(result).toBe(false)
    expect(consoleSpy).toHaveBeenCalledWith(
      '[isPluginActive] Error checking plugin status for my-plugin:',
      expect.any(Error)
    )
    consoleSpy.mockRestore()
  })
})

describe('requireActivePlugin', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
  })

  it('should not throw when plugin is active', async () => {
    mockDb._mocks.first.mockResolvedValue({ status: 'active' })

    await expect(
      requireActivePlugin(mockDb as any, 'my-plugin')
    ).resolves.not.toThrow()
  })

  it('should throw when plugin is not active', async () => {
    mockDb._mocks.first.mockResolvedValue({ status: 'inactive' })

    await expect(
      requireActivePlugin(mockDb as any, 'my-plugin')
    ).rejects.toThrow("Plugin 'my-plugin' is required but is not active")
  })

  it('should throw when plugin does not exist', async () => {
    mockDb._mocks.first.mockResolvedValue(null)

    await expect(
      requireActivePlugin(mockDb as any, 'nonexistent')
    ).rejects.toThrow("Plugin 'nonexistent' is required but is not active")
  })

  it('should throw with correct plugin name in message', async () => {
    mockDb._mocks.first.mockResolvedValue(null)

    await expect(
      requireActivePlugin(mockDb as any, 'special-plugin-123')
    ).rejects.toThrow("Plugin 'special-plugin-123' is required but is not active")
  })
})

describe('requireActivePlugins', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
  })

  it('should not throw when all plugins are active', async () => {
    mockDb._mocks.first.mockResolvedValue({ status: 'active' })

    await expect(
      requireActivePlugins(mockDb as any, ['plugin-a', 'plugin-b', 'plugin-c'])
    ).resolves.not.toThrow()

    expect(mockDb._mocks.bind).toHaveBeenCalledTimes(3)
    expect(mockDb._mocks.bind).toHaveBeenNthCalledWith(1, 'plugin-a')
    expect(mockDb._mocks.bind).toHaveBeenNthCalledWith(2, 'plugin-b')
    expect(mockDb._mocks.bind).toHaveBeenNthCalledWith(3, 'plugin-c')
  })

  it('should throw when first plugin is not active', async () => {
    mockDb._mocks.first.mockResolvedValue({ status: 'inactive' })

    await expect(
      requireActivePlugins(mockDb as any, ['plugin-a', 'plugin-b'])
    ).rejects.toThrow("Plugin 'plugin-a' is required but is not active")
  })

  it('should throw when second plugin is not active', async () => {
    mockDb._mocks.first
      .mockResolvedValueOnce({ status: 'active' })
      .mockResolvedValueOnce({ status: 'inactive' })

    await expect(
      requireActivePlugins(mockDb as any, ['plugin-a', 'plugin-b'])
    ).rejects.toThrow("Plugin 'plugin-b' is required but is not active")
  })

  it('should not throw with empty plugins array', async () => {
    await expect(
      requireActivePlugins(mockDb as any, [])
    ).resolves.not.toThrow()

    expect(mockDb._mocks.prepare).not.toHaveBeenCalled()
  })

  it('should check plugins in order', async () => {
    mockDb._mocks.first
      .mockResolvedValueOnce({ status: 'active' })
      .mockResolvedValueOnce({ status: 'active' })
      .mockResolvedValueOnce(null)

    await expect(
      requireActivePlugins(mockDb as any, ['a', 'b', 'c'])
    ).rejects.toThrow("Plugin 'c' is required but is not active")

    // Should have checked all three
    expect(mockDb._mocks.bind).toHaveBeenCalledTimes(3)
  })
})

describe('getActivePlugins', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
  })

  it('should return array of active plugins', async () => {
    const mockPlugins = [
      { id: 'plugin-a', name: 'Plugin A', status: 'active', version: '1.0.0' },
      { id: 'plugin-b', name: 'Plugin B', status: 'active', version: '2.0.0' }
    ]
    mockDb._mocks.all.mockResolvedValue({ results: mockPlugins })

    const result = await getActivePlugins(mockDb as any)

    expect(result).toEqual(mockPlugins)
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith(
      `SELECT slug as id, json_extract(data, '$.status') as status, data FROM documents
         WHERE type_id = 'plugin' AND tenant_id = 'default'
           AND q_plugin_status = 'active' AND is_current_draft = 1 AND deleted_at IS NULL`
    )
  })

  it('should return empty array when no active plugins', async () => {
    mockDb._mocks.all.mockResolvedValue({ results: [] })

    const result = await getActivePlugins(mockDb as any)

    expect(result).toEqual([])
  })

  it('should return empty array when results is null', async () => {
    mockDb._mocks.all.mockResolvedValue({ results: null })

    const result = await getActivePlugins(mockDb as any)

    expect(result).toEqual([])
  })

  it('should return empty array when results is undefined', async () => {
    mockDb._mocks.all.mockResolvedValue({})

    const result = await getActivePlugins(mockDb as any)

    expect(result).toEqual([])
  })

  it('should return empty array and log error on database error', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockDb._mocks.all.mockRejectedValue(new Error('DB error'))

    const result = await getActivePlugins(mockDb as any)

    expect(result).toEqual([])
    expect(consoleSpy).toHaveBeenCalledWith(
      '[getActivePlugins] Error fetching active plugins:',
      expect.any(Error)
    )
    consoleSpy.mockRestore()
  })

  it('should return all plugin fields from database', async () => {
    const mockPlugins = [
      {
        id: 'full-plugin',
        name: 'Full Plugin',
        status: 'active',
        version: '1.0.0',
        description: 'A test plugin',
        config: '{"key": "value"}',
        created_at: 1234567890,
        updated_at: 1234567890
      }
    ]
    mockDb._mocks.all.mockResolvedValue({ results: mockPlugins })

    const result = await getActivePlugins(mockDb as any)

    expect(result).toEqual(mockPlugins)
    expect(result[0].id).toBe('full-plugin')
    expect(result[0].config).toBe('{"key": "value"}')
  })
})
