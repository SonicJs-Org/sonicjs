import { beforeEach, describe, expect, it, vi } from 'vitest'
import { PluginService } from '../../services/plugin-service'

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

function createPluginRow(overrides: Record<string, unknown> = {}) {
  return {
    id: 'core-auth',
    name: 'core-auth',
    display_name: 'Authentication',
    description: 'Core auth plugin',
    version: '1.0.0',
    author: 'SonicJS Team',
    category: 'security',
    icon: '🔐',
    status: 'active',
    is_core: 1,
    settings: '{"registration":{"enabled":true}}',
    permissions: '["auth:manage"]',
    dependencies: '["email"]',
    download_count: '10',
    rating: '4.5',
    installed_at: '100',
    activated_at: '110',
    last_updated: '120',
    error_message: null,
    ...overrides
  }
}

describe('PluginService', () => {
  let pluginService: PluginService
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    pluginService = new PluginService(mockDb as never)
    vi.clearAllMocks()
  })

  it('parses plugin rows into typed plugin data', async () => {
    mockDb._mocks.first.mockResolvedValue(createPluginRow())

    const plugin = await pluginService.getPlugin('core-auth')

    expect(plugin).toEqual({
      id: 'core-auth',
      name: 'core-auth',
      display_name: 'Authentication',
      description: 'Core auth plugin',
      version: '1.0.0',
      author: 'SonicJS Team',
      category: 'security',
      icon: '🔐',
      status: 'active',
      is_core: true,
      settings: { registration: { enabled: true } },
      permissions: ['auth:manage'],
      dependencies: ['email'],
      download_count: 10,
      rating: 4.5,
      installed_at: 100,
      activated_at: 110,
      last_updated: 120,
      error_message: undefined
    })
  })

  it('coerces plugin stats row values to numbers', async () => {
    mockDb._mocks.first.mockResolvedValue({
      total: '7',
      active: '3',
      inactive: '2',
      errors: '1'
    })

    const stats = await pluginService.getPluginStats()

    expect(stats).toEqual({
      total: 7,
      active: 3,
      inactive: 2,
      errors: 1,
      uninstalled: 0
    })
  })

  it('parses plugin activity details as structured JSON', async () => {
    mockDb._mocks.all.mockResolvedValue({
      results: [
        {
          id: 'activity-1',
          action: 'installed',
          user_id: 'user-1',
          details: '{"version":"1.0.0","source":"registry"}',
          timestamp: '1234'
        }
      ]
    })

    const activity = await pluginService.getPluginActivity('core-auth')

    expect(activity).toEqual([
      {
        id: 'activity-1',
        action: 'installed',
        userId: 'user-1',
        details: { version: '1.0.0', source: 'registry' },
        timestamp: 1234
      }
    ])
  })

  it('throws when plugin settings contain invalid JSON for the expected shape', async () => {
    mockDb._mocks.first.mockResolvedValue(createPluginRow({ settings: '["not-an-object"]' }))

    await expect(pluginService.getPlugin('core-auth')).rejects.toThrow(/Invalid plugins\.settings/)
  })
})
