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
import { getCollectionRegistry } from '../services/collection-registry'

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
    const baseEndpoints = buildRouteList(app)

    // Inject per-collection routes from the in-memory registry.
    // These replace the generic /:collection wildcards that inspectRoutes returns.
    const collectionRoutes: typeof baseEndpoints = []
    const collections = getCollectionRegistry().listActive().filter(r => !r.internal)
    const methodOrder: Record<string, number> = { GET: 0, POST: 1, PUT: 2, PATCH: 3, DELETE: 4 }
    for (const col of collections) {
      const displayName = col.displayName || col.name
      collectionRoutes.push(
        { method: 'GET',    path: `/api/${col.slug || col.name}`,     description: `List ${displayName} items`,     authentication: false, category: 'Collections', documented: true },
        { method: 'GET',    path: `/api/${col.slug || col.name}/:id`, description: `Get a ${displayName} by ID`,    authentication: false, category: 'Collections', documented: true },
        { method: 'POST',   path: `/api/${col.slug || col.name}`,     description: `Create a ${displayName}`,       authentication: true,  category: 'Collections', documented: true },
        { method: 'PUT',    path: `/api/${col.slug || col.name}/:id`, description: `Update a ${displayName}`,       authentication: true,  category: 'Collections', documented: true },
        { method: 'DELETE', path: `/api/${col.slug || col.name}/:id`, description: `Delete a ${displayName}`,       authentication: true,  category: 'Collections', documented: true },
      )
    }

    // Remove any auto-discovered wildcard /:collection entries (too generic) and merge in specific ones
    const wildcardPaths = new Set(['/api/:collection', '/api/:collection/:id'])
    const filteredBase = baseEndpoints.filter(e => !wildcardPaths.has(e.path))
    const endpoints = [...filteredBase, ...collectionRoutes].sort((a, b) => {
      const catCmp = a.category.localeCompare(b.category)
      if (catCmp !== 0) return catCmp
      const mOrder: Record<string, number> = { GET: 0, POST: 1, PUT: 2, PATCH: 3, DELETE: 4 }
      const methCmp = (mOrder[a.method] ?? 5) - (mOrder[b.method] ?? 5)
      if (methCmp !== 0) return methCmp
      return a.path.localeCompare(b.path)
    })

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
