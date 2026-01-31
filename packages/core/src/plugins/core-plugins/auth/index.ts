/**
 * Core Auth Plugin
 * 
 * Provides authentication and authorization extensions
 */

import { Hono } from 'hono'
import { PluginBuilder } from '../../sdk/plugin-builder'
import { Plugin, HOOKS } from '@sonicjs-cms/core'

export function createAuthPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: 'core-auth',
    version: '1.0.0-beta.1',
    description: 'Core authentication and authorization plugin'
  })

  // Add auth metadata
  builder.metadata({
    author: {
      name: 'SonicJS Team',
      email: 'team@sonicjs.com'
    },
    license: 'MIT',
    compatibility: '^0.1.0'
  })

  // Create auth API routes (Better Auth owns sign-in/sign-out; this plugin exposes compatibility)
  const authAPI = new Hono()

  // GET /api/auth/me - Current user from session (set by global middleware)
  authAPI.get('/me', async (c) => {
    const user = (c.get as (k: string) => { userId: string; email: string; role: string } | undefined)('user')
    if (!user) {
      return c.json({ error: 'Authentication required' }, 401)
    }
    return c.json({
      message: 'Current user info',
      user: { id: user.userId, email: user.email, role: user.role }
    })
  })

  // POST /api/auth/login - Deprecated: use Better Auth POST /auth/sign-in/email
  authAPI.post('/login', async (c) => {
    return c.json(
      { error: 'Use Better Auth: POST /auth/sign-in/email with { email, password }' },
      410
    )
  })

  // POST /api/auth/logout - Deprecated: use Better Auth POST /auth/sign-out
  authAPI.post('/logout', async (c) => {
    return c.json(
      { message: 'Use Better Auth: POST /auth/sign-out to sign out' },
      200
    )
  })

  // POST /api/auth/refresh - Deprecated: Better Auth manages session refresh
  authAPI.post('/refresh', async (c) => {
    return c.json(
      { message: 'Session is managed by Better Auth; no separate refresh needed' },
      200
    )
  })

  builder.addRoute('/api/auth', authAPI, {
    description: 'Authentication API endpoints',
    priority: 1
  })

  // Add auth middleware (session is set by global Better Auth middleware; this is for x-session-id only)
  builder.addSingleMiddleware('auth-session', async (c: { req: { header: (name: string) => string | undefined }; set: (key: string, value: unknown) => void }, next: () => Promise<void>) => {
    const sessionId = c.req.header('x-session-id')
    if (sessionId) {
      c.set('sessionId', sessionId)
    }
    await next()
  }, {
    description: 'Session management middleware',
    global: true,
    priority: 5
  })

  builder.addSingleMiddleware('auth-rate-limit', async (c: { req: { path: string; header: (name: string) => string | undefined } }, next: () => Promise<void>) => {
    if (c.req.path.startsWith('/api/auth/')) {
      const clientIP = c.req.header('CF-Connecting-IP') || 'unknown'
      console.debug(`Auth rate limit check for IP: ${clientIP}`)
    }
    await next()
  }, {
    description: 'Rate limiting for authentication endpoints',
    routes: ['/api/auth/*'],
    priority: 3
  })

  // Add auth service (stub for plugin compatibility; main auth is Better Auth)
  builder.addService('authService', {
    validateToken: (_token: string) => ({ valid: false, userId: null as number | null }),
    generateToken: (_userId: number) => '',
    hashPassword: (_password: string) => '',
    verifyPassword: (_password: string, _hash: string) => false
  }, {
    description: 'Core authentication service (Better Auth is source of truth)',
    singleton: true
  })

  // Add auth hooks
  builder.addHook('auth:login', async (data: { email?: string }) => {
    console.info(`User login attempt: ${data.email ?? 'unknown'}`)
    return data
  }, {
    priority: 10,
    description: 'Handle user login events'
  })

  builder.addHook('auth:logout', async (data: { userId?: string }) => {
    console.info(`User logout: ${data.userId ?? 'unknown'}`)
    return data
  }, {
    priority: 10,
    description: 'Handle user logout events'
  })

  builder.addHook(HOOKS.REQUEST_START, async (data: { request?: { headers?: { authorization?: string } }; authenticated?: boolean }) => {
    const authHeader = data.request?.headers?.authorization
    if (authHeader) {
      data.authenticated = true
    }
    return data
  }, {
    priority: 5,
    description: 'Track authentication status on requests'
  })

  // Add admin pages
  builder.addAdminPage(
    '/auth/sessions',
    'Active Sessions',
    'AuthSessionsView',
    {
      description: 'View and manage active user sessions',
      permissions: ['admin', 'auth:manage'],
      icon: 'users'
    }
  )

  builder.addAdminPage(
    '/auth/tokens',
    'API Tokens',
    'AuthTokensView',
    {
      description: 'Manage API tokens and access keys',
      permissions: ['admin', 'auth:manage'],
      icon: 'key'
    }
  )

  // Add menu items
  builder.addMenuItem('Authentication', '/admin/auth', {
    icon: 'shield',
    order: 20,
    permissions: ['admin', 'auth:manage']
  })

  builder.addMenuItem('Sessions', '/admin/auth/sessions', {
    icon: 'users',
    parent: 'Authentication',
    order: 1,
    permissions: ['admin', 'auth:manage']
  })

  builder.addMenuItem('API Tokens', '/admin/auth/tokens', {
    icon: 'key',
    parent: 'Authentication',
    order: 2,
    permissions: ['admin', 'auth:manage']
  })

  // Add lifecycle hooks
  builder.lifecycle({
    install: async () => {
      console.info('Installing auth plugin...')
      // Create auth-related database tables or configurations
    },

    activate: async () => {
      console.info('Activating auth plugin...')
      // Initialize auth services and middleware
    },

    deactivate: async () => {
      console.info('Deactivating auth plugin...')
      // Clean up auth resources
    },

    configure: async (config) => {
      console.info('Configuring auth plugin...', config)
      // Apply configuration changes
    }
  })

  return builder.build() as Plugin as Plugin
}

// Export the plugin instance
export const authPlugin = createAuthPlugin()