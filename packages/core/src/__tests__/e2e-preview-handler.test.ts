import { describe, expect, it, vi } from 'vitest'
import { previewFetch } from '../../../../tests/e2e/utils/preview-handler'

const request = (path: string, key = 'owned', method = 'GET') => new Request(`https://preview.invalid${path}`, {
  method, headers: { 'X-E2E-Run-Key': key },
})
function environment() {
  return { E2E_RUN_KEY: 'owned', E2E_BUILD_SHA: 'abc123', E2E_RESOURCE_NAME: 'sonicjs-e2e-123-1',
    MEDIA_BUCKET: { list: vi.fn(async () => ({ objects: [{ key: 'a' }], truncated: false })), delete: vi.fn(async () => {}) } }
}
describe('disposable preview wrapper', () => {
  it('fails closed without the run key and does not call application or storage', async () => {
    const env = environment()
    const app = vi.fn()
    expect((await previewFetch(request('/__e2e__/identity', 'wrong'), env, app)).status).toBe(403)
    expect(env.MEDIA_BUCKET.list).not.toHaveBeenCalled()
    expect(app).not.toHaveBeenCalled()
  })
  it('reports the build actually bound to this worker, not HTTP 200 alone', async () => {
    const res = await previewFetch(request('/__e2e__/identity'), environment(), vi.fn())
    expect(await res.json()).toEqual({ sha: 'abc123', resource: 'sonicjs-e2e-123-1' })
  })
  it('deletes only the run-bound bucket and preserves normal app handling', async () => {
    const env = environment()
    expect((await previewFetch(request('/__e2e__/storage', 'owned', 'DELETE'), env, vi.fn())).status).toBe(200)
    expect(env.MEDIA_BUCKET.delete).toHaveBeenCalledExactlyOnceWith(['a'])
    const app = vi.fn(async () => new Response('real application'))
    expect(await (await previewFetch(request('/admin'), env, app)).text()).toBe('real application')
    expect(app).toHaveBeenCalledTimes(1)
  })
})
