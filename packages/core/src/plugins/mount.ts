/**
 * Mount a registered user plugin onto a Hono app.
 *
 * Middleware is sorted by priority (lower runs earlier). When `global` is set
 * or `routes` is empty, middleware applies to '*'; otherwise each entry in
 * `routes` becomes a scoped `app.use(path, handler)` registration.
 *
 * Routes are mounted in declaration order via `app.route(path, handler)`.
 */

import type { Hono } from 'hono'
import type { Plugin } from './types'

export function mountPlugin(app: Hono<any, any, any>, plugin: Plugin): void {
  const middleware = [...(plugin.middleware ?? [])].sort(
    (a, b) => (a.priority ?? 100) - (b.priority ?? 100)
  )

  for (const m of middleware) {
    if (m.global || !m.routes || m.routes.length === 0) {
      app.use('*', m.handler)
    } else {
      for (const path of m.routes) {
        app.use(path, m.handler)
      }
    }
  }

  for (const route of plugin.routes ?? []) {
    app.route(route.path, route.handler as any)
  }
}
