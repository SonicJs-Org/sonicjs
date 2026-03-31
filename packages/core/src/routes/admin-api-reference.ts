/**
 * Admin API Reference Routes
 *
 * Provides the API Reference page for the admin dashboard.
 * Uses auto-discovery via Hono's inspectRoutes() to always show
 * the complete list of registered API endpoints.
 */

import { Hono } from 'hono'
import type { D1Database, KVNamespace, R2Bucket } from '@cloudflare/workers-types'
import { requireAuth } from '../middleware'
import {
  renderAPIReferencePage,
  type APIReferencePageData
} from '../templates/pages/admin-api-reference.template'
import { getCoreVersion } from '../utils/version'
import { buildRouteList, getAppInstance } from '../services/route-metadata'

const VERSION = getCoreVersion()

type Bindings = {
  DB: D1Database
  CACHE_KV: KVNamespace
  MEDIA_BUCKET: R2Bucket
}

type Variables = {
  user?: {
    userId: string
    email: string
    role: string
  }
}

const router = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware
router.use('*', requireAuth())

/**
 * GET /admin/api-reference - API Reference Page
 *
 * Auto-discovers all registered routes using Hono's inspectRoutes()
 * and enriches them with metadata from the route-metadata registry.
 */
router.get('/', async (c) => {
  const user = c.get('user')

  try {
    const app = getAppInstance()
    const endpoints = buildRouteList(app)

    const pageData: APIReferencePageData = {
      endpoints,
      user: user ? {
        name: user.email.split('@')[0] || user.email,
        email: user.email,
        role: user.role
      } : undefined,
      version: VERSION
    }

    return c.html(renderAPIReferencePage(pageData))
  } catch (error) {
    console.error('API Reference page error:', error)

    const pageData: APIReferencePageData = {
      endpoints: [],
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined,
      version: VERSION
    }

    return c.html(renderAPIReferencePage(pageData))
  }
})

export { router as adminApiReferenceRoutes }
