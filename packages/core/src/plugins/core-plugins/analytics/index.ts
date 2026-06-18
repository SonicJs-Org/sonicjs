/**
 * Core Analytics Plugin — document-model backed.
 *
 * Events are stored as `analytics_event` documents. Stub-only hardcoded
 * `/api/analytics/*` routes removed; real event tracking lives at `/api/events`.
 * Legacy non-typed hooks (request:start, request:end, user:login, content:view)
 * subscribe via the raw bus in onBoot.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { analyticsAdminRoutes } from './routes/admin'
import { eventsApiRoutes } from './routes/api'

export const analyticsPlugin = definePlugin({
  id: 'core-analytics',
  version: '1.0.0',
  name: 'Analytics',
  description: 'Core analytics tracking and reporting plugin.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  register(app) {
    app.route('/api/events', eventsApiRoutes as any)
    app.route('/admin/analytics', analyticsAdminRoutes as any)
  },

  menu: [
    {
      label: 'Analytics',
      path: '/admin/analytics',
      icon: 'chart',
      order: 40,
      permissions: ['admin', 'analytics:read'],
    },
  ],

  async onBoot(ctx) {
    const hooks = (ctx.raw as any)?.hooks
    if (!hooks?.register) return
    hooks.register('request:start', async (data: any) => {
      data.analytics = {
        startTime: Date.now(),
        sessionId: `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      }
      return data
    }, 1)
    hooks.register('request:end', async (data: any) => {
      if (data.analytics) {
        const duration = Date.now() - data.analytics.startTime
        console.debug(`Request completed in ${duration}ms`)
      }
      return data
    }, 1)
    hooks.register('user:login', async (data: any, context: any) => {
      await context.services?.analyticsService?.trackEvent({
        eventType: 'auth',
        eventName: 'user_login',
        userId: data.userId,
        eventData: { loginMethod: data.method },
      })
      return data
    }, 8)
    hooks.register('content:view', async (data: any, context: any) => {
      await context.services?.analyticsService?.trackEvent({
        eventType: 'content',
        eventName: 'content_view',
        eventData: { contentId: data.id, contentType: data.type, title: data.title },
      })
      return data
    }, 8)
  },
})

export function createAnalyticsPlugin() {
  return analyticsPlugin
}
