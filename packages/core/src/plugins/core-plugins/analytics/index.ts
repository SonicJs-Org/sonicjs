/**
 * Core Analytics Plugin
 * 
 * Provides analytics tracking and reporting extensions
 */

import { Hono } from 'hono'
// import { z } from 'zod'
import { PluginBuilder, PluginHelpers } from '../../sdk/plugin-builder'
import type { Plugin } from '../../types'
import { HOOKS } from '../../types'
import { analyticsAdminRoutes } from './routes/admin'

export function createAnalyticsPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: 'core-analytics',
    version: '1.0.0-beta.1',
    description: 'Core analytics tracking and reporting plugin'
  })

  // Add analytics metadata
  builder.metadata({
    author: {
      name: 'SonicJS Team',
      email: 'team@sonicjs.com'
    },
    license: 'MIT',
    compatibility: '^0.1.0',
    dependencies: ['core-auth'] // Requires auth for admin access
  })

  // Create analytics API routes
  const analyticsAPI = new Hono()

  // GET /analytics/stats - Get analytics overview
  analyticsAPI.get('/stats', async (c) => {
    const timeRange = c.req.query('range') || '7d' // 1d, 7d, 30d, 90d
    const _metric = c.req.query('metric') || 'all' // pageviews, sessions, users, etc.

    return c.json({
      message: 'Analytics stats',
      data: {
        pageviews: 12500,
        uniqueVisitors: 3200,
        sessions: 4800,
        avgSessionDuration: 245,
        bounceRate: 0.35,
        topPages: [
          { path: '/', views: 3200 },
          { path: '/about', views: 1800 },
          { path: '/contact', views: 950 }
        ],
        timeRange
      }
    })
  })

  // POST /analytics/track - Track analytics event
  analyticsAPI.post('/track', async (c) => {
    const event = await c.req.json()
    
    // Track event (pageview, click, form submission, etc.)
    console.info('Analytics event tracked:', event)
    
    return c.json({
      message: 'Event tracked successfully',
      eventId: `event-${Date.now()}`
    })
  })

  // GET /analytics/reports - Get detailed reports
  analyticsAPI.get('/reports', async (c) => {
    const reportType = c.req.query('type') || 'traffic'
    const startDate = c.req.query('start')
    const endDate = c.req.query('end')

    return c.json({
      message: 'Analytics report',
      data: {
        reportType,
        dateRange: { start: startDate, end: endDate },
        data: []
      }
    })
  })

  // GET /analytics/realtime - Get real-time analytics
  analyticsAPI.get('/realtime', async (c) => {
    return c.json({
      message: 'Real-time analytics',
      data: {
        activeUsers: 23,
        activePages: [
          { path: '/', users: 8 },
          { path: '/blog', users: 5 },
          { path: '/products', users: 4 }
        ],
        recentEvents: []
      }
    })
  })

  builder.addRoute('/api/analytics', analyticsAPI, {
    description: 'Analytics tracking and reporting API',
    requiresAuth: true,
    roles: ['admin', 'analytics:read'],
    priority: 3
  })

  // Admin dashboard routes
  builder.addRoute('/admin/analytics', analyticsAdminRoutes as any, {
    description: 'Analytics admin dashboard',
    requiresAuth: true,
    priority: 50
  })

  // Add analytics tracking middleware
  builder.addSingleMiddleware('analytics-tracker', async (c: any, next: any) => {
    const start = Date.now()
    const path = c.req.path
    const method = c.req.method
    const userAgent = c.req.header('user-agent')
    const referer = c.req.header('referer')
    const ip = c.req.header('CF-Connecting-IP') || c.req.header('x-forwarded-for')

    await next()

    const duration = Date.now() - start
    const status = c.res.status

    // Track request analytics
    const analyticsData = {
      timestamp: new Date().toISOString(),
      path,
      method,
      status,
      duration,
      userAgent,
      referer,
      ip,
      responseSize: c.res.headers.get('content-length') || 0
    }

    console.debug('Analytics tracking:', analyticsData)
    
    // Store analytics data (would integrate with analytics service)
  }, {
    description: 'Track page views and request analytics',
    global: true,
    priority: 99 // Run last to capture response data
  })

  // Add analytics service
  builder.addService('analyticsService', {
    trackEvent: async (event: any) => {
      // Event tracking implementation
      console.info('Tracking event:', event)
      return { eventId: `event-${Date.now()}` }
    },
    
    trackPageView: async (data: any) => {
      // Page view tracking implementation
      console.info('Tracking pageview:', data.path)
      return { viewId: `view-${Date.now()}` }
    },
    
    getStats: async (_timeRange: string) => {
      // Get analytics statistics
      return {
        pageviews: 12500,
        sessions: 4800,
        uniqueVisitors: 3200
      }
    },
    
    generateReport: async (type: string, options: any) => {
      // Generate analytics reports
      console.info(`Generating ${type} report with options:`, options)
      return { reportId: `report-${Date.now()}` }
    }
  }, {
    description: 'Core analytics tracking service',
    singleton: true
  })

  // Add analytics models
  const pageViewSchema = PluginHelpers.createSchema([
    { name: 'path', type: 'string', optional: false },
    { name: 'title', type: 'string', optional: true },
    { name: 'referrer', type: 'string', optional: true },
    { name: 'userAgent', type: 'string', optional: true },
    { name: 'ipAddress', type: 'string', optional: true },
    { name: 'sessionId', type: 'string', optional: true },
    { name: 'userId', type: 'number', optional: true },
    { name: 'duration', type: 'number', optional: true }
  ])

  const eventSchema = PluginHelpers.createSchema([
    { name: 'eventType', type: 'string', optional: false },
    { name: 'eventName', type: 'string', optional: false },
    { name: 'eventData', type: 'object', optional: true },
    { name: 'path', type: 'string', optional: true },
    { name: 'sessionId', type: 'string', optional: true },
    { name: 'userId', type: 'number', optional: true }
  ])

  const pageViewMigration = PluginHelpers.createMigration('analytics_pageviews', [
    { name: 'id', type: 'INTEGER', primaryKey: true },
    { name: 'path', type: 'TEXT', nullable: false },
    { name: 'title', type: 'TEXT', nullable: true },
    { name: 'referrer', type: 'TEXT', nullable: true },
    { name: 'user_agent', type: 'TEXT', nullable: true },
    { name: 'ip_address', type: 'TEXT', nullable: true },
    { name: 'session_id', type: 'TEXT', nullable: true },
    { name: 'user_id', type: 'INTEGER', nullable: true },
    { name: 'duration', type: 'INTEGER', nullable: true }
  ])

  const eventMigration = PluginHelpers.createMigration('analytics_events', [
    { name: 'id', type: 'INTEGER', primaryKey: true },
    { name: 'event_type', type: 'TEXT', nullable: false },
    { name: 'event_name', type: 'TEXT', nullable: false },
    { name: 'event_data', type: 'TEXT', nullable: true },
    { name: 'path', type: 'TEXT', nullable: true },
    { name: 'session_id', type: 'TEXT', nullable: true },
    { name: 'user_id', type: 'INTEGER', nullable: true }
  ])

  builder.addModel('PageView', {
    tableName: 'analytics_pageviews',
    schema: pageViewSchema,
    migrations: [pageViewMigration]
  })

  builder.addModel('AnalyticsEvent', {
    tableName: 'analytics_events',
    schema: eventSchema,
    migrations: [eventMigration]
  })

  // Add analytics hooks
  builder.addHook(HOOKS.REQUEST_START, async (data: any, _context: any) => {
    // Start tracking request
    data.analytics = {
      startTime: Date.now(),
      sessionId: `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    }
    return data
  }, {
    priority: 1,
    description: 'Initialize analytics tracking for requests'
  })

  builder.addHook(HOOKS.REQUEST_END, async (data: any, _context: any) => {
    // Complete request tracking
    if (data.analytics) {
      const duration = Date.now() - data.analytics.startTime
      console.debug(`Request completed in ${duration}ms`)
    }
    return data
  }, {
    priority: 1,
    description: 'Complete analytics tracking for requests'
  })

  builder.addHook(HOOKS.USER_LOGIN, async (data: any, context: any) => {
    // Track user login events
    await context.services?.analyticsService?.trackEvent({
      eventType: 'auth',
      eventName: 'user_login',
      userId: data.userId,
      eventData: { loginMethod: data.method }
    })
    return data
  }, {
    priority: 8,
    description: 'Track user login events'
  })

  builder.addHook('content:view', async (data: any, context: any) => {
    // Track content views
    await context.services?.analyticsService?.trackEvent({
      eventType: 'content',
      eventName: 'content_view',
      eventData: {
        contentId: data.id,
        contentType: data.type,
        title: data.title
      }
    })
    return data
  }, {
    priority: 8,
    description: 'Track content view events'
  })

  // Add admin pages
  builder.addAdminPage(
    '/analytics',
    'Analytics Dashboard',
    'AnalyticsDashboardView',
    {
      description: 'View analytics overview and key metrics',
      permissions: ['admin', 'analytics:read'],
      icon: 'chart-bar'
    }
  )

  builder.addAdminPage(
    '/analytics/reports',
    'Analytics Reports',
    'AnalyticsReportsView',
    {
      description: 'Generate and view detailed analytics reports',
      permissions: ['admin', 'analytics:read'],
      icon: 'document-report'
    }
  )

  builder.addAdminPage(
    '/analytics/realtime',
    'Real-time Analytics',
    'AnalyticsRealtimeView',
    {
      description: 'View real-time visitor activity',
      permissions: ['admin', 'analytics:read'],
      icon: 'lightning-bolt'
    }
  )

  builder.addAdminPage(
    '/analytics/settings',
    'Analytics Settings',
    'AnalyticsSettingsView',
    {
      description: 'Configure analytics tracking and data collection',
      permissions: ['admin', 'analytics:configure'],
      icon: 'cog'
    }
  )

  // Add menu items
  builder.addMenuItem('Analytics', '/admin/analytics', {
    icon: 'chart-bar',
    order: 40,
    permissions: ['admin', 'analytics:read']
  })

  builder.addMenuItem('Dashboard', '/admin/analytics', {
    icon: 'chart-bar',
    parent: 'Analytics',
    order: 1,
    permissions: ['admin', 'analytics:read']
  })

  builder.addMenuItem('Reports', '/admin/analytics/reports', {
    icon: 'document-report',
    parent: 'Analytics',
    order: 2,
    permissions: ['admin', 'analytics:read']
  })

  builder.addMenuItem('Real-time', '/admin/analytics/realtime', {
    icon: 'lightning-bolt',
    parent: 'Analytics',
    order: 3,
    permissions: ['admin', 'analytics:read']
  })

  builder.addMenuItem('Settings', '/admin/analytics/settings', {
    icon: 'cog',
    parent: 'Analytics',
    order: 4,
    permissions: ['admin', 'analytics:configure']
  })

  // Add lifecycle hooks
  builder.lifecycle({
    install: async () => {
      console.info('Installing analytics plugin...')
      // Create analytics database tables and initial configuration
    },

    activate: async () => {
      console.info('Activating analytics plugin...')
      // Start analytics tracking services
    },

    deactivate: async () => {
      console.info('Deactivating analytics plugin...')
      // Stop analytics tracking and clean up resources
    },

    configure: async (config) => {
      console.info('Configuring analytics plugin...', config)
      // Update analytics configuration and settings
    }
  })

  return builder.build() as Plugin
}

// Export the plugin instance
export const analyticsPlugin = createAnalyticsPlugin()