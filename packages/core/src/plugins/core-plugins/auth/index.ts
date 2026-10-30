/**
 * Core Auth Plugin — Payload-shaped port.
 *
 * Stub-grade authentication API + auth-event hooks. The real auth flow lives
 * in Better Auth (see app.ts /auth/* catch-all). The historical addService /
 * addSingleMiddleware / addAdminPage declarations on this plugin were never
 * wired by the runtime; they are dropped in this port.
 */

import { Hono } from 'hono'
import { definePlugin } from '../../sdk/define-plugin'

const authAPI = new Hono()

authAPI.post('/login', async (c) => {
  const { email } = await c.req.json()
  return c.json({ message: 'Login endpoint', data: { email } })
})

authAPI.post('/logout', async (c) => {
  return c.json({ message: 'Logout successful' })
})

authAPI.get('/me', async (c) => {
  return c.json({ message: 'Current user info', user: { id: 1, email: 'user@example.com' } })
})

authAPI.post('/refresh', async (c) => {
  return c.json({ message: 'Token refreshed' })
})

export const authPlugin = definePlugin({
  id: 'core-auth',
  version: '1.0.0',
  name: 'Authentication',
  description: 'Core authentication and authorization plugin.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  register(app) {
    app.route('/api/auth', authAPI)
  },

  menu: [
    {
      label: 'Authentication',
      path: '/admin/auth',
      icon: 'lock',
      order: 20,
      permissions: ['admin', 'auth:manage'],
    },
  ],

  async onBoot(ctx) {
    // Legacy non-typed auth-event hooks — subscribe via the raw bus.
    const hooks = (ctx.raw as any)?.hooks
    if (!hooks?.register) return
    hooks.register('auth:login', async (data: any) => {
      console.info(`User login attempt: ${data.email}`)
      return data
    }, 10)
    hooks.register('auth:logout', async (data: any) => {
      console.info(`User logout: ${data.userId}`)
      return data
    }, 10)
    hooks.register('request:start', async (data: any) => {
      const authHeader = data.request?.headers?.authorization
      if (authHeader) data.authenticated = true
      return data
    }, 5)
  },

  install: async () => console.info('Installing auth plugin...'),
  activate: async () => console.info('Activating auth plugin...'),
  deactivate: async () => console.info('Deactivating auth plugin...'),
})

export function createAuthPlugin() {
  return authPlugin
}
