import { createHash } from 'node:crypto'
import type { APIRequestContext } from '@playwright/test'

function isLocal(origin: string): boolean {
  return ['localhost', '127.0.0.1', '[::1]'].includes(new URL(origin).hostname)
}

/** Keep one local client per file, including hooks, with the real limiter enabled. */
export function localClientHeaders(
  origin: string,
  file: string,
  headers: Record<string, string>,
): Record<string, string> {
  if (!isLocal(origin)) return headers
  if (Object.keys(headers).some(key => ['x-forwarded-for', 'cf-connecting-ip'].includes(key.toLowerCase()))) return headers
  const hash = createHash('sha256').update(file).digest('hex')
  const address = `2001:db8:${hash.slice(0, 4)}:${hash.slice(4, 8)}:${hash.slice(8, 12)}:${hash.slice(12, 16)}:0:1`
  return { ...headers, 'CF-Connecting-IP': address }
}

const PREPARED = Symbol('sonicjs.e2e.local-client')

/** Decorate only same-origin API calls. Browser/CDN traffic is never modified.
 * Keep response identity, explicit options and one mutation per call. No retries.
 * Remote targets retain the edge's real client identity without any decoration.
 */
export function prepareLocalRequest(
  request: APIRequestContext,
  origin: string,
  file: string,
  configuredHeaders: Record<string, string> = {},
): APIRequestContext {
  if (!isLocal(origin)) return request
  const marked = request as unknown as Record<symbol, boolean>
  if (marked[PREPARED]) return request
  marked[PREPARED] = true
  const fetch = request.fetch.bind(request)
  request.fetch = (urlOrRequest, options = {}) => {
    const url = new URL(typeof urlOrRequest === 'string' ? urlOrRequest : urlOrRequest.url(), origin)
    if (url.origin !== new URL(origin).origin) return fetch(urlOrRequest, options)
    const headers = { ...configuredHeaders, ...options.headers }
    const isolated = localClientHeaders(origin, file, headers)
    if (isolated === headers) return fetch(urlOrRequest, options)
    return fetch(urlOrRequest, { ...options, headers: { ...options.headers, 'CF-Connecting-IP': isolated['CF-Connecting-IP'] } })
  }
  return request
}
