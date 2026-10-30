import { Hono } from 'hono'
import { createYoga } from 'graphql-yoga'
import type { Bindings, Variables } from '../../../../app'
import { getDocumentRequestContext } from '../../../../services/document-request-context'
import { buildSchema } from '../schema'
import type { GraphqlResolverContext } from '../resolvers/context'
import type { GraphqlConfig } from '../config'

export function createGraphqlRoutes(config: GraphqlConfig) {
  const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

  const yoga = createYoga<{ bindings: Bindings; variables: Variables }, GraphqlResolverContext>({
    schema: buildSchema,
    graphiql: config.playground,
    // Yoga derives context from the 2nd arg passed to yoga.fetch().
    // We inject db, tenantId, principalSet here so resolvers never touch Hono internals.
    context: async ({ request: _req, ...serverCtx }) => {
      const { bindings, variables } = serverCtx as { bindings: Bindings; variables: Variables }
      const db = bindings?.DB
      // Build a minimal Hono-like context stub for getDocumentRequestContext.
      // variables carries the session user set by the auth middleware in app.ts.
      const user = variables?.user
      const tenantId = (variables as any)?.tenantId ?? 'default'

      const principalSet = user?.userId
        ? [
            { type: 'user' as const, id: user.userId },
            ...(user.role ? [{ type: 'role' as const, id: user.role }] : []),
          ]
        : [{ type: 'public' as const, id: '*' }]

      return {
        db,
        tenantId,
        principalSet,
        userId: user?.userId ?? null,
      }
    },
  })

  // Mount: Yoga handles both GET (playground) and POST (execute).
  // Pass CF bindings + request variables as the second arg to yoga.fetch so the context
  // factory above can resolve db, user, tenantId without coupling to Hono internals.
  app.all('/', async (c) => {
    if (config.requireAuth && !c.get('user')) {
      return c.json({ errors: [{ message: 'Unauthorized: provide a valid API key' }] }, 401)
    }

    const serverCtx = { bindings: c.env, variables: c.var }
    return yoga.fetch(c.req.raw, serverCtx) as unknown as Response
  })

  return app
}
