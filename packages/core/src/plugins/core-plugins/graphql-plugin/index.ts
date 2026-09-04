/**
 * GraphQL Plugin — exposes SonicJS documents via a GraphQL API.
 *
 * Opt-in: add `graphqlPlugin()` to the app's `plugins.register` array.
 * Endpoint: POST /graphql (execute queries/mutations)
 *           GET  /graphql (GraphiQL playground, when enabled)
 *
 * Authentication is delegated to the app-wide apiKeyAuthMiddleware — callers present
 * `Authorization: Bearer sk_…`. Resolvers enforce document ACL per-operation.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { createGraphqlRoutes } from './routes/graphql'
import { resolveGraphqlConfig, type GraphqlConfigInput } from './config'

const GQL_ICON = `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>`

export function graphqlPlugin(options: GraphqlConfigInput = {}) {
  const config = resolveGraphqlConfig(options)

  return definePlugin({
    id: 'graphql',
    version: '1.0.0',
    name: 'GraphQL API',
    description: 'Exposes SonicJS documents via a GraphQL endpoint with optional GraphiQL playground.',
    sonicjsVersionRange: '^3.0.0',
    author: { name: 'SonicJS Team' },

    register(app) {
      app.route('/graphql', createGraphqlRoutes(config) as any)
    },

    menu: [{ label: 'GraphQL', path: '/graphql', icon: GQL_ICON, order: 88 }],
  })
}

export { resolveGraphqlConfig } from './config'
export type { GraphqlConfigInput, GraphqlConfig } from './config'

export default graphqlPlugin
