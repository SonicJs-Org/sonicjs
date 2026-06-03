import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Hono } from 'hono'
import { adminPluginRoutes } from '../../routes/admin-plugins'

// Helper to create mock user with specific role
const createMockUser = (role: string = 'admin') => ({
  id: 'test-user',
  email: 'test@example.com',
  role
})

// Store the mock role so tests can change it
let mockUserRole = 'admin'

// Store the mock plugin service methods so tests can modify them
let mockGetAllPlugins: any
let mockGetPluginStats: any
let mockGetPlugin: any
let mockGetPluginActivity: any
let mockActivatePlugin: any
let mockDeactivatePlugin: any
let mockInstallPlugin: any
let mockUninstallPlugin: any
let mockUpdatePluginSettings: any

// Default plugin data
const createDefaultPlugins = () => [
  {
    id: 'email',
    name: 'email',
    display_name: 'Email',
    description: 'Send transactional emails using Resend',
    version: '1.0.0-beta.1',
    author: 'SonicJS Team',
    category: 'communication',
    icon: '📧',
    status: 'inactive',
    is_core: true,
    permissions: ['email:manage', 'email:send'],
    dependencies: [],
    installed_at: Date.now(),
    last_updated: Math.floor(Date.now() / 1000),
    download_count: 100,
    rating: 4.5
  },
  {
    id: 'auth',
    name: 'auth',
    display_name: 'Authentication',
    description: 'User authentication and authorization',
    version: '1.0.0',
    author: 'SonicJS Team',
    category: 'security',
    icon: '🔐',
    status: 'active',
    is_core: true,
    permissions: ['auth:manage'],
    dependencies: [],
    installed_at: Date.now(),
    last_updated: Math.floor(Date.now() / 1000),
    download_count: 500,
    rating: 5.0
  }
]

// Mock the requireAuth middleware to bypass authentication in tests
vi.mock('../../middleware', () => ({
  requireAuth: () => {
    return async (c: any, next: any) => {
      c.set('user', createMockUser(mockUserRole))
      await next()
    }
  }
}))

// Plugin access now gates on RBAC (`plugins:manage`) instead of the legacy
// `user.role === 'admin'` string. Drive can() from the same mockUserRole the
// tests already toggle, so admin → allowed and non-admin → denied.
vi.mock('../../services/rbac', () => ({
  RbacService: class {
    can = async () => mockUserRole === 'admin'
  }
}))

// Mock the manifest registry so test plugin names are recognized
vi.mock('../../plugins/manifest-registry', () => {
  const makeEntry = (id: string, codeName?: string, adminMenu?: any) => ({
    id,
    codeName: codeName || id,
    displayName: id,
    description: `Test plugin ${id}`,
    version: '1.0.0',
    author: 'Test',
    category: 'general',
    iconEmoji: '',
    is_core: false,
    permissions: [],
    dependencies: [],
    defaultSettings: {},
    adminMenu: adminMenu || null,
  })

  const PLUGIN_REGISTRY: Record<string, any> = {
    'email': makeEntry('email', 'email'),
    'auth': makeEntry('auth', 'auth'),
    'faq-plugin': makeEntry('faq-plugin', 'faq-plugin'),
    'demo-login-plugin': makeEntry('demo-login-plugin', 'demo-login-plugin'),
    'core-auth': makeEntry('core-auth', 'core-auth'),
    'core-media': makeEntry('core-media', 'core-media'),
    'core-workflow': makeEntry('core-workflow', 'core-workflow'),
    'database-tools': makeEntry('database-tools', 'database-tools'),
    'seed-data': makeEntry('seed-data', 'seed-data'),
    'quill-editor': makeEntry('quill-editor', 'quill-editor'),
    'tinymce-plugin': makeEntry('tinymce-plugin', 'tinymce-plugin'),
    'easy-mdx': makeEntry('easy-mdx', 'easy-mdx'),
    'turnstile-plugin': makeEntry('turnstile-plugin', 'turnstile-plugin'),
  }

  return {
    PLUGIN_REGISTRY,
    ALL_PLUGIN_IDS: Object.keys(PLUGIN_REGISTRY),
    PLUGINS_WITH_ADMIN_PAGES: [],
    findPluginByCodeName: (codeName: string) =>
      Object.values(PLUGIN_REGISTRY).find((p: any) => p.codeName === codeName) || PLUGIN_REGISTRY[codeName],
    getPlugin: (id: string) => PLUGIN_REGISTRY[id],
  }
})

// Mock the PluginService as a class
vi.mock('../../services', () => ({
  PluginService: class MockPluginService {
    getAllPlugins() {
      return mockGetAllPlugins()
    }
    getPluginStats() {
      return mockGetPluginStats()
    }
    getPlugin(id: string) {
      return mockGetPlugin(id)
    }
    getPluginActivity(id: string, limit: number) {
      return mockGetPluginActivity(id, limit)
    }
    activatePlugin(id: string) {
      return mockActivatePlugin(id)
    }
    deactivatePlugin(id: string) {
      return mockDeactivatePlugin(id)
    }
    installPlugin(data: any) {
      return mockInstallPlugin(data)
    }
    uninstallPlugin(id: string) {
      return mockUninstallPlugin(id)
    }
    updatePluginSettings(id: string, settings: any) {
      return mockUpdatePluginSettings(id, settings)
    }
  }
}))

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
  KV: {},
  CACHE_KV: {}
})

describe('Admin Plugins Routes', () => {
  let app: Hono
  let mockEnv: any

  beforeEach(() => {
    vi.clearAllMocks()
    mockEnv = createMockEnv()
    mockUserRole = 'admin'

    // Reset all mock functions
    mockGetAllPlugins = vi.fn().mockResolvedValue(createDefaultPlugins())
    mockGetPluginStats = vi.fn().mockResolvedValue({
      total: 2,
      active: 1,
      inactive: 1,
      errors: 0,
      uninstalled: 0
    })
    mockGetPlugin = vi.fn().mockResolvedValue({
      id: 'email',
      name: 'email',
      display_name: 'Email',
      description: 'Send transactional emails using Resend',
      version: '1.0.0-beta.1',
      author: 'SonicJS Team',
      category: 'communication',
      icon: '📧',
      status: 'inactive',
      is_core: true,
      permissions: ['email:manage'],
      dependencies: [],
      last_updated: Math.floor(Date.now() / 1000),
      download_count: 100,
      rating: 4.5,
      settings: { apiKey: 'test-key' }
    })
    mockGetPluginActivity = vi.fn().mockResolvedValue([
      {
        id: '1',
        action: 'installed',
        message: 'Plugin installed',
        timestamp: Date.now(),
        user_email: 'admin@example.com'
      }
    ])
    mockActivatePlugin = vi.fn().mockResolvedValue(undefined)
    mockDeactivatePlugin = vi.fn().mockResolvedValue(undefined)
    mockInstallPlugin = vi.fn().mockResolvedValue({
      id: 'faq-plugin',
      name: 'faq-plugin',
      status: 'active'
    })
    mockUninstallPlugin = vi.fn().mockResolvedValue(undefined)
    mockUpdatePluginSettings = vi.fn().mockResolvedValue(undefined)

    // Create new app instance for each test
    app = new Hono<{ Bindings: { DB: any; KV: any; CACHE_KV: any } }>()

    // Set up middleware to provide env and app context
    app.use('*', async (c, next) => {
      // @ts-ignore - Setting env for test purposes
      c.env = mockEnv
      c.set('appVersion', '1.0.0-test')
      await next()
    })

    // Mount admin plugin routes
    app.route('/admin/plugins', adminPluginRoutes)
  })

  describe('GET /admin/plugins (list page)', () => {
    it('should return plugins list page with email plugin', async () => {
      const res = await app.request('/admin/plugins', {
        method: 'GET',
        headers: {
          'Content-Type': 'text/html'
        }
      })

      expect(res.status).toBe(200)

      const html = await res.text()
      expect(html).toContain('Email')
      expect(html).toContain('Send transactional emails using Resend')
      expect(html).toContain('Authentication')
    })

    it('should display correct plugin statistics', async () => {
      const res = await app.request('/admin/plugins', {
        method: 'GET'
      })

      expect(res.status).toBe(200)
      const html = await res.text()
      expect(html).toContain('2') // Total plugins
    })

    it('should deny access for non-admin users', async () => {
      mockUserRole = 'user'

      const res = await app.request('/admin/plugins', {
        method: 'GET'
      })

      expect(res.status).toBe(403)
      const text = await res.text()
      expect(text).toBe('Access denied')
    })

    it('should handle errors when loading plugins gracefully', async () => {
      mockGetAllPlugins = vi.fn().mockRejectedValue(new Error('Database error'))

      const res = await app.request('/admin/plugins', {
        method: 'GET'
      })

      // Should still return 200 with empty plugins
      expect(res.status).toBe(200)
    })
  })

  describe('GET /admin/plugins/:id (settings page)', () => {
    // Note: Tests that require full template rendering are skipped in unit tests
    // due to template module dependencies. These are covered by e2e tests.

    it('should return 404 for non-existent plugin', async () => {
      mockGetPlugin = vi.fn().mockResolvedValue(null)

      const res = await app.request('/admin/plugins/non-existent', {
        method: 'GET'
      })

      expect(res.status).toBe(404)
      const text = await res.text()
      expect(text).toBe('Plugin not found')
    })

    it('should redirect non-admin users', async () => {
      mockUserRole = 'user'

      const res = await app.request('/admin/plugins/email', {
        method: 'GET'
      })

      expect(res.status).toBe(302)
      expect(res.headers.get('location')).toBe('/admin/plugins')
    })
  })

  describe('POST /admin/plugins/:id/activate', () => {
    it('should activate a plugin successfully', async () => {
      const res = await app.request('/admin/plugins/email/activate', {
        method: 'POST'
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
      expect(mockActivatePlugin).toHaveBeenCalledWith('email')
    })

    it('should deny access for non-admin users', async () => {
      mockUserRole = 'user'

      const res = await app.request('/admin/plugins/email/activate', {
        method: 'POST'
      })

      expect(res.status).toBe(403)
      const json = await res.json()
      expect(json.error).toBe('Access denied')
    })

    it('should handle activation errors', async () => {
      mockActivatePlugin = vi.fn().mockRejectedValue(new Error('Activation failed'))

      const res = await app.request('/admin/plugins/email/activate', {
        method: 'POST'
      })

      expect(res.status).toBe(400)
      const json = await res.json()
      expect(json.error).toBe('Activation failed')
    })
  })

  describe('POST /admin/plugins/:id/deactivate', () => {
    it('should deactivate a plugin successfully', async () => {
      const res = await app.request('/admin/plugins/auth/deactivate', {
        method: 'POST'
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
      expect(mockDeactivatePlugin).toHaveBeenCalledWith('auth')
    })

    it('should deny access for non-admin users', async () => {
      mockUserRole = 'user'

      const res = await app.request('/admin/plugins/auth/deactivate', {
        method: 'POST'
      })

      expect(res.status).toBe(403)
      const json = await res.json()
      expect(json.error).toBe('Access denied')
    })

    it('should handle deactivation errors', async () => {
      mockDeactivatePlugin = vi.fn().mockRejectedValue(new Error('Cannot deactivate core plugin'))

      const res = await app.request('/admin/plugins/auth/deactivate', {
        method: 'POST'
      })

      expect(res.status).toBe(400)
      const json = await res.json()
      expect(json.error).toBe('Cannot deactivate core plugin')
    })
  })

  describe('POST /admin/plugins/install', () => {
    it('should install faq-plugin successfully', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'faq-plugin' })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
      expect(mockInstallPlugin).toHaveBeenCalled()
    })

    it('should install demo-login-plugin successfully', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'demo-login-plugin' })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
    })

    it('should install core-auth plugin successfully', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'core-auth' })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
    })

    it('should install core-media plugin successfully', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'core-media' })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
    })

    it('should install core-workflow plugin successfully', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'core-workflow' })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
    })

    it('should install database-tools plugin successfully', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'database-tools' })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
    })

    it('should install seed-data plugin successfully', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'seed-data' })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
    })

    it('should install quill-editor plugin successfully', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'quill-editor' })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
    })

    it('should install tinymce-plugin successfully', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'tinymce-plugin' })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
    })

    it('should install easy-mdx plugin successfully', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'easy-mdx' })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
    })

    it('should install turnstile-plugin successfully', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'turnstile-plugin' })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
    })

    it('should return 404 for unknown plugin', async () => {
      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'unknown-plugin' })
      })

      expect(res.status).toBe(404)
      const json = await res.json()
      expect(json.error).toBe('Plugin not found in registry')
    })

    it('should deny access for non-admin users', async () => {
      mockUserRole = 'user'

      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'faq-plugin' })
      })

      expect(res.status).toBe(403)
      const json = await res.json()
      expect(json.error).toBe('Access denied')
    })

    it('should handle installation errors', async () => {
      mockInstallPlugin = vi.fn().mockRejectedValue(new Error('Installation failed'))

      const res = await app.request('/admin/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'faq-plugin' })
      })

      expect(res.status).toBe(400)
      const json = await res.json()
      expect(json.error).toBe('Installation failed')
    })
  })

  describe('POST /admin/plugins/:id/uninstall', () => {
    it('should uninstall a plugin successfully', async () => {
      const res = await app.request('/admin/plugins/email/uninstall', {
        method: 'POST'
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
      expect(mockUninstallPlugin).toHaveBeenCalledWith('email')
    })

    it('should deny access for non-admin users', async () => {
      mockUserRole = 'user'

      const res = await app.request('/admin/plugins/email/uninstall', {
        method: 'POST'
      })

      expect(res.status).toBe(403)
      const json = await res.json()
      expect(json.error).toBe('Access denied')
    })

    it('should handle uninstall errors', async () => {
      mockUninstallPlugin = vi.fn().mockRejectedValue(new Error('Cannot uninstall core plugin'))

      const res = await app.request('/admin/plugins/email/uninstall', {
        method: 'POST'
      })

      expect(res.status).toBe(400)
      const json = await res.json()
      expect(json.error).toBe('Cannot uninstall core plugin')
    })
  })

  describe('POST /admin/plugins/:id/settings', () => {
    it('should update plugin settings successfully', async () => {
      const res = await app.request('/admin/plugins/email/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey: 'new-api-key', enabled: true })
      })

      expect(res.status).toBe(200)
      const json = await res.json()
      expect(json.success).toBe(true)
      expect(mockUpdatePluginSettings).toHaveBeenCalledWith('email', {
        apiKey: 'new-api-key',
        enabled: true
      })
    })

    it('should deny access for non-admin users', async () => {
      mockUserRole = 'user'

      const res = await app.request('/admin/plugins/email/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey: 'test' })
      })

      expect(res.status).toBe(403)
      const json = await res.json()
      expect(json.error).toBe('Access denied')
    })

    it('should handle settings update errors', async () => {
      mockUpdatePluginSettings = vi.fn().mockRejectedValue(new Error('Invalid settings'))

      const res = await app.request('/admin/plugins/email/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey: 'test' })
      })

      expect(res.status).toBe(400)
      const json = await res.json()
      expect(json.error).toBe('Invalid settings')
    })
  })

  // Note: formatLastUpdated is tested implicitly through the plugin list page tests.
  // Direct unit tests for formatLastUpdated would require exporting the function,
  // which is currently a private helper in admin-plugins.ts
})
