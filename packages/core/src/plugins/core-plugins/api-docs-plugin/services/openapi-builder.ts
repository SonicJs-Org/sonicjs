/**
 * OpenAPI 3.0 spec builder.
 *
 * The one piece SonicJS core is missing: a transform from the live route list
 * (the core `buildRouteList(getAppInstance())` output) into an OpenAPI 3.0
 * document. Everything upstream — route auto-discovery, the metadata registry,
 * category + auth inference — is reused from `services/route-metadata`; this
 * file only shapes that `RouteMetadata[]` into a spec.
 *
 * Pure and app-free by design (takes the already-built route list), so it can
 * be unit-tested without an assembled app. The admin route calls
 * `buildRouteList(getAppInstance())` and hands the result here.
 *
 * NOTE: this is the "thin" spec — operations carry summaries, tags, path
 * params, a generic JSON request/response body, and per-route security. It does
 * NOT (yet) inject per-collection field schemas from D1; that enrichment is a
 * deliberate follow-up (see the plugin's delivery plan, F2).
 */
import { CATEGORY_INFO, type RouteMetadata } from '../../../../services'

/** OpenAPI operation object (only the fields this builder emits). */
interface OpenApiOperation {
  summary: string
  tags: string[]
  responses: Record<string, unknown>
  security?: Array<Record<string, string[]>>
  parameters?: Array<Record<string, unknown>>
  requestBody?: Record<string, unknown>
}

const BODY_METHODS = new Set(['post', 'put', 'patch'])

/** `:param` → `{param}` and a trailing `/*` wildcard → `/{path}` for OpenAPI. */
function toOpenApiPath(path: string): string {
  return path
    .replace(/:([a-zA-Z_][a-zA-Z0-9_]*)/g, '{$1}')
    .replace(/\/\*$/, '/{path}')
}

/** Path parameters declared in a route, in OpenAPI parameter-object form. */
function pathParameters(path: string): Array<Record<string, unknown>> {
  const params: Array<Record<string, unknown>> = []
  const named = path.match(/:([a-zA-Z_][a-zA-Z0-9_]*)/g)
  if (named) {
    for (const p of named) {
      params.push({ name: p.slice(1), in: 'path', required: true, schema: { type: 'string' } })
    }
  }
  // Trailing wildcard becomes a single {path} segment.
  if (/\/\*$/.test(path)) {
    params.push({ name: 'path', in: 'path', required: true, schema: { type: 'string' } })
  }
  return params
}

function buildOperation(route: RouteMetadata): OpenApiOperation {
  const method = route.method.toLowerCase()

  const operation: OpenApiOperation = {
    summary: route.description || `${route.method} ${route.path}`,
    tags: [route.category],
    responses: {
      '200': {
        description: 'Successful response',
        content: { 'application/json': { schema: { type: 'object' } } },
      },
    },
  }

  // Authenticated routes advertise the bearer scheme. `'unknown'` is left open.
  if (route.authentication === true) {
    operation.security = [{ bearerAuth: [] }]
  }

  const params = pathParameters(route.path)
  if (params.length > 0) {
    operation.parameters = params
  }

  if (BODY_METHODS.has(method)) {
    operation.requestBody = {
      content: { 'application/json': { schema: { type: 'object' } } },
    }
  }

  return operation
}

/**
 * Build an OpenAPI 3.0 document from the live route list.
 *
 * @param routes    result of `buildRouteList(getAppInstance())`
 * @param serverUrl origin the spec is served from (for the `servers` block)
 * @param version   SonicJS core version (for `info.version`)
 */
export function buildApiDocsOpenApiSpec(
  routes: RouteMetadata[],
  serverUrl: string,
  version: string,
): object {
  // Tags from the categories actually in use, enriched from CATEGORY_INFO.
  const tagSet = new Set<string>()
  for (const r of routes) tagSet.add(r.category)
  const tags = Array.from(tagSet)
    .sort()
    .map((name) => ({ name, description: CATEGORY_INFO[name]?.description ?? '' }))

  // Paths: group operations by OpenAPI-shaped path.
  const paths: Record<string, Record<string, unknown>> = {}
  for (const route of routes) {
    const openApiPath = toOpenApiPath(route.path)
    if (!paths[openApiPath]) paths[openApiPath] = {}
    paths[openApiPath]![route.method.toLowerCase()] = buildOperation(route)
  }

  return {
    openapi: '3.0.0',
    info: {
      title: 'SonicJS AI API',
      version,
      description:
        'RESTful API for SonicJS — a modern, AI-powered headless CMS built on Cloudflare Workers. Auto-discovered from the registered route table.',
      contact: { name: 'SonicJS Support', url: `${serverUrl}/docs`, email: 'support@sonicjs.com' },
      license: { name: 'MIT', url: 'https://opensource.org/licenses/MIT' },
    },
    servers: [{ url: serverUrl, description: 'Current server' }],
    tags,
    paths,
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      },
    },
  }
}
