/** Test-only Worker wrapper. Never imported into production application code. */
export interface PreviewEnvironment {
  E2E_RUN_KEY?: string
  E2E_BUILD_SHA?: string
  E2E_RESOURCE_NAME?: string
  MEDIA_BUCKET: {
    list(options: { limit: number; cursor?: string }): Promise<{
      objects: Array<{ key: string }>; truncated: boolean; cursor?: string
    }>
    delete(keys: string[]): Promise<unknown>
  }
}

export async function previewFetch(
  request: Request,
  env: PreviewEnvironment,
  application: () => Promise<Response>,
): Promise<Response> {
  const path = new URL(request.url).pathname
  if (!path.startsWith('/__e2e__/')) return application()
  if (!env.E2E_RUN_KEY || request.headers.get('X-E2E-Run-Key') !== env.E2E_RUN_KEY ||
      !/^sonicjs-e2e-\d+-\d+$/.test(env.E2E_RESOURCE_NAME ?? '')) {
    return new Response('Forbidden', { status: 403 })
  }
  if (path === '/__e2e__/identity' && request.method === 'GET') {
    return Response.json({ sha: env.E2E_BUILD_SHA, resource: env.E2E_RESOURCE_NAME })
  }
  if (path === '/__e2e__/storage' && request.method === 'DELETE') {
    let cursor: string | undefined
    for (let page = 0; page < 1_000; page++) {
      const listed = await env.MEDIA_BUCKET.list({ limit: 1_000, cursor })
      if (listed.objects.length) await env.MEDIA_BUCKET.delete(listed.objects.map(object => object.key))
      if (!listed.truncated) return Response.json({ success: true })
      if (!listed.cursor) throw new Error('R2 cleanup returned a truncated page without a cursor')
      cursor = listed.cursor
    }
    throw new Error('R2 cleanup exceeded its bounded page limit')
  }
  return new Response('Not found', { status: 404 })
}
