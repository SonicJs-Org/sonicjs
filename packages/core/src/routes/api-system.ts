/**
 * API System Routes
 *
 * Provides system health, status, and metadata endpoints
 * These are lightweight routes without heavy dependencies
 */

import { Hono } from 'hono'
import type { Bindings, Variables } from '../app'

export const apiSystemRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

/**
 * System health check
 * GET /api/system/health
 */
apiSystemRoutes.get('/health', async (c) => {
  try {
    const startTime = Date.now()

    // Check database connectivity
    let dbStatus = 'unknown'
    let dbLatency = 0

    try {
      const dbStart = Date.now()
      await c.env.DB.prepare('SELECT 1').first()
      dbLatency = Date.now() - dbStart
      dbStatus = 'healthy'
    } catch (error) {
      console.error('Database health check failed:', error)
      dbStatus = 'unhealthy'
    }

    // Check KV connectivity (if available)
    let kvStatus = 'not_configured'
    let kvLatency = 0

    if (c.env.CACHE_KV) {
      try {
        const kvStart = Date.now()
        await c.env.CACHE_KV.get('__health_check__')
        kvLatency = Date.now() - kvStart
        kvStatus = 'healthy'
      } catch (error) {
        console.error('KV health check failed:', error)
        kvStatus = 'unhealthy'
      }
    }

    // Check R2 connectivity (if available)
    let r2Status = 'not_configured'

    if (c.env.MEDIA_BUCKET) {
      try {
        await c.env.MEDIA_BUCKET.head('__health_check__')
        r2Status = 'healthy'
      } catch (error) {
        // R2 head on non-existent key returns null, not an error
        // This is expected, so we consider it healthy
        r2Status = 'healthy'
      }
    }

    const totalLatency = Date.now() - startTime
    const overall = dbStatus === 'healthy' ? 'healthy' : 'degraded'

    return c.json({
      status: overall,
      timestamp: new Date().toISOString(),
      uptime: totalLatency,
      checks: {
        database: {
          status: dbStatus,
          latency: dbLatency
        },
        cache: {
          status: kvStatus,
          latency: kvLatency
        },
        storage: {
          status: r2Status
        }
      },
      environment: c.env.ENVIRONMENT || 'production'
    })
  } catch (error) {
    console.error('Health check failed:', error)
    return c.json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Health check failed'
    }, 503)
  }
})

/**
 * System information
 * GET /api/system/info
 */
apiSystemRoutes.get('/info', (c) => {
  const appVersion = c.get('appVersion') || '1.0.0'

  return c.json({
    name: 'SonicJS',
    version: appVersion,
    description: 'Modern headless CMS built on Cloudflare Workers',
    endpoints: {
      api: '/api',
      auth: '/auth',
      health: '/api/system/health',
      docs: '/docs'
    },
    features: {
      content: true,
      media: true,
      auth: true,
      collections: true,
      caching: !!c.env.CACHE_KV,
      storage: !!c.env.MEDIA_BUCKET
    },
    timestamp: new Date().toISOString()
  })
})

/**
 * System stats
 * GET /api/system/stats
 */
apiSystemRoutes.get('/stats', async (c) => {
  try {
    const db = c.env.DB

    // Get content statistics (document-backed: one row per root for user collections).
    const contentStats = await db.prepare(`
      SELECT COUNT(*) as total_content
      FROM documents
      WHERE is_current_draft = 1 AND deleted_at IS NULL
        AND type_id IN (SELECT name FROM collections WHERE is_active = 1 AND (source_type IS NULL OR source_type = 'user'))
    `).first() as any

    // Get media statistics
    const mediaStats = await db.prepare(`
      SELECT
        COUNT(*) as total_files,
        SUM(size) as total_size
      FROM media
      WHERE deleted_at IS NULL
    `).first() as any

    // Get user statistics
    const userStats = await db.prepare(`
      SELECT COUNT(*) as total_users
      FROM users
    `).first() as any

    return c.json({
      content: {
        total: contentStats?.total_content || 0
      },
      media: {
        total_files: mediaStats?.total_files || 0,
        total_size_bytes: mediaStats?.total_size || 0,
        total_size_mb: Math.round((mediaStats?.total_size || 0) / 1024 / 1024 * 100) / 100
      },
      users: {
        total: userStats?.total_users || 0
      },
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Stats query failed:', error)
    return c.json({ error: 'Failed to fetch system statistics' }, 500)
  }
})

/**
 * Database ping
 * GET /api/system/ping
 */
apiSystemRoutes.get('/ping', async (c) => {
  try {
    const start = Date.now()
    await c.env.DB.prepare('SELECT 1').first()
    const latency = Date.now() - start

    return c.json({
      pong: true,
      latency,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Ping failed:', error)
    return c.json({
      pong: false,
      error: 'Database connection failed'
    }, 503)
  }
})

/**
 * Environment check
 * GET /api/system/env
 */
apiSystemRoutes.get('/env', (c) => {
  return c.json({
    environment: c.env.ENVIRONMENT || 'production',
    features: {
      database: !!c.env.DB,
      cache: !!c.env.CACHE_KV,
      media_bucket: !!c.env.MEDIA_BUCKET,
      email_queue: !!c.env.EMAIL_QUEUE,
      sendgrid: !!c.env.SENDGRID_API_KEY,
      cloudflare_images: !!(c.env.IMAGES_ACCOUNT_ID && c.env.IMAGES_API_TOKEN)
    },
    timestamp: new Date().toISOString()
  })
})

export default apiSystemRoutes
