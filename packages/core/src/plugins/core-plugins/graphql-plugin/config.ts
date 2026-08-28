export interface GraphqlConfigInput {
  /**
   * Enable GraphQL introspection. Defaults to true.
   * Disable in production if you don't want schema exposed publicly.
   */
  introspection?: boolean
  /**
   * Enable GraphiQL playground at GET /graphql. Defaults to true.
   * Disable in production to serve only POST queries.
   */
  playground?: boolean
  /**
   * Require authentication for all GraphQL requests.
   * When true, unauthenticated requests receive an Unauthorized error.
   * When false (default), introspection is allowed unauthenticated
   * but resolvers still enforce ACL per document type.
   */
  requireAuth?: boolean
}

export interface GraphqlConfig {
  introspection: boolean
  playground: boolean
  requireAuth: boolean
}

export function resolveGraphqlConfig(input: GraphqlConfigInput = {}): GraphqlConfig {
  return {
    introspection: input.introspection ?? true,
    playground: input.playground ?? true,
    requireAuth: input.requireAuth ?? false,
  }
}
