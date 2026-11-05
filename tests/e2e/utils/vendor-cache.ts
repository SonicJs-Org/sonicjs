import type { APIRequestContext, BrowserContext } from '@playwright/test'

type VendorResponse = { status: number; headers: Record<string, string>; body: Buffer }
const responses = new Map<string, VendorResponse>()
const PREPARED = Symbol('sonicjs.e2e.vendor-cache')

export function isVendorAsset(url: URL): boolean {
  if (url.protocol !== 'https:') return false
  if (url.hostname === 'cdn.tailwindcss.com' || url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com') return true
  if (url.hostname === 'cdn.jsdelivr.net') return url.pathname.startsWith('/npm/')
  if (url.hostname === 'cdnjs.cloudflare.com') return url.pathname.startsWith('/ajax/libs/')
  return url.hostname === 'unpkg.com' && /^\/(?:htmx\.org|alpinejs|quill|easymde|@mdxeditor\/editor)(?:@|\/|$)/.test(url.pathname)
}

/** Cache original public asset responses in worker memory, never application data.
 * Keep redirects, status, CORS and content headers. Strip transport encoding after
 * reading decoded bytes; fulfill computes the correct body length. No retries,
 * substituted libraries, persisted files, app routes or remote-target interception.
 */
export async function cacheVendorAssets(context: BrowserContext, origin: string, client?: APIRequestContext): Promise<void> {
  if (!['localhost', '127.0.0.1', '[::1]'].includes(new URL(origin).hostname)) return
  const marked = context as unknown as Record<symbol, Promise<void> | undefined>
  if (marked[PREPARED]) return marked[PREPARED]
  // Pending requests belong to their context; only completed bytes cross contexts.
  // Normal context teardown can cancel a background font without failing a test.
  const pendingResponses = new Map<string, Promise<VendorResponse>>()
  let closed = false
  context.once('close', () => { closed = true })
  marked[PREPARED] = context.route(isVendorAsset, async route => {
    const request = route.request()
    if (request.method() !== 'GET') return route.continue()
    const requestHeaders = request.headers()
    const key = JSON.stringify([request.url(), requestHeaders['user-agent'], requestHeaders.accept, requestHeaders.origin])
    let pending = pendingResponses.get(key)
    if (!pending) {
      pending = responses.has(key) ? Promise.resolve(responses.get(key)!) : (async () => {
        const options = { maxRedirects: 0, maxRetries: 0 }
        const response = client
          ? await client.get(request.url(), { ...options, headers: { ...requestHeaders, 'accept-encoding': 'gzip, deflate, br' } })
          : await route.fetch(options)
        const headers = { ...response.headers() }
        for (const name of ['content-encoding', 'content-length', 'transfer-encoding', 'connection']) delete headers[name]
        return { status: response.status(), headers, body: await response.body() }
      })()
      pendingResponses.set(key, pending)
    }
    try {
      const response = await pending
      if (response.status >= 200 && response.status < 400 && response.status !== 304) responses.set(key, response)
      if (closed) return
      await route.fulfill({ ...response, headers: { ...response.headers } })
    } catch (error) {
      if (closed) return
      throw error
    } finally {
      pendingResponses.delete(key)
    }
  })
  await marked[PREPARED]
}
