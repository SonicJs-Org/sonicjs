import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Context } from 'hono'
import { rateLimit, rateLimitClientKey } from '../../middleware/rate-limit'

function ctx(headers: Record<string, string>, kv?: unknown) {
  const sent: Record<string, string> = {}
  return {
    env: { CACHE_KV: kv },
    req: { header: (name: string) => headers[name.toLowerCase()] },
    header: (k: string, v: string) => { sent[k] = v },
    json: (body: unknown, status: number) => ({ body, status }),
    _sent: sent,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- minimal Hono context stand-in
  } as any as Context & { _sent: Record<string, string> }
}

describe('rateLimitClientKey', () => {
  it('prefers cf-connecting-ip, which the Cloudflare edge overwrites and the client cannot forge', () => {
    expect(
      rateLimitClientKey(ctx({ 'cf-connecting-ip': '9.9.9.9', 'x-forwarded-for': '1.1.1.1' }))
    ).toBe('9.9.9.9')
  })

  it('buckets a single-hop x-forwarded-for on that hop', () => {
    expect(rateLimitClientKey(ctx({ 'x-forwarded-for': '1.2.3.4' }))).toBe('1.2.3.4')
  })

  it('takes the rightmost hop, so a prepended forgery cannot mint a fresh bucket', () => {
    // The attack: a caller on a non-Cloudflare deployment prepends a random value per request.
    // Read verbatim, every attempt counted against its own key and the limiter was a no-op.
    const forged = ['evil-1', 'evil-2', 'evil-3'].map((f) =>
      rateLimitClientKey(ctx({ 'x-forwarded-for': `${f}, 203.0.113.7` }))
    )
    expect(new Set(forged)).toEqual(new Set(['203.0.113.7']))
  })

  it('does not split one client across two buckets on hop-count alone', () => {
    // `"1.2.3.4, 5.6.7.8"` and `"5.6.7.8"` are the same client seen through one more proxy.
    expect(rateLimitClientKey(ctx({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8' }))).toBe(
      rateLimitClientKey(ctx({ 'x-forwarded-for': '5.6.7.8' }))
    )
  })

  it('tolerates whitespace and empty hops', () => {
    expect(rateLimitClientKey(ctx({ 'x-forwarded-for': ' 1.2.3.4 ,  , 5.6.7.8  ' }))).toBe('5.6.7.8')
    expect(rateLimitClientKey(ctx({ 'x-forwarded-for': ' , ' }))).toBe('unknown')
  })

  it('falls back to a shared bucket when no address is available', () => {
    expect(rateLimitClientKey(ctx({}))).toBe('unknown')
  })
})

describe('rateLimit', () => {
  let store: Map<string, string>
  let kv: { get: ReturnType<typeof vi.fn>; put: ReturnType<typeof vi.fn> }

  beforeEach(() => {
    store = new Map()
    kv = {
      get: vi.fn(async (k: string) => {
        const raw = store.get(k)
        return raw ? JSON.parse(raw) : null
      }),
      put: vi.fn(async (k: string, v: string) => { store.set(k, v) }),
    }
  })

  it('passes through untouched when no KV binding is bound', async () => {
    const next = vi.fn(async () => {})
    await rateLimit({ max: 1, windowMs: 1000, keyPrefix: 'login' })(ctx({}, undefined), next)
    await rateLimit({ max: 1, windowMs: 1000, keyPrefix: 'login' })(ctx({}, undefined), next)
    expect(next).toHaveBeenCalledTimes(2)
  })

  it('rejects with 429 once the window budget is spent', async () => {
    const mw = rateLimit({ max: 2, windowMs: 60_000, keyPrefix: 'login' })
    const headers = { 'cf-connecting-ip': '1.2.3.4' }
    const next = vi.fn(async () => {})

    await mw(ctx(headers, kv), next)
    await mw(ctx(headers, kv), next)
    expect(next).toHaveBeenCalledTimes(2)

    const rejected = await mw(ctx(headers, kv), next)
    expect(next).toHaveBeenCalledTimes(2)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- stubbed c.json returns a plain object
    expect((rejected as any).status).toBe(429)
  })

  it('counts a forged x-forwarded-for prefix against one bucket, not one bucket per request', async () => {
    const mw = rateLimit({ max: 2, windowMs: 60_000, keyPrefix: 'login' })
    const next = vi.fn(async () => {})

    for (let i = 0; i < 2; i++) {
      await mw(ctx({ 'x-forwarded-for': `forged-${i}, 203.0.113.7` }, kv), next)
    }
    const rejected = await mw(ctx({ 'x-forwarded-for': 'forged-3, 203.0.113.7' }, kv), next)

    expect(next).toHaveBeenCalledTimes(2)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- stubbed c.json returns a plain object
    expect((rejected as any).status).toBe(429)
    expect([...store.keys()]).toEqual(['ratelimit:login:203.0.113.7'])
  })

  it('keeps distinct clients in distinct buckets', async () => {
    const mw = rateLimit({ max: 1, windowMs: 60_000, keyPrefix: 'login' })
    const next = vi.fn(async () => {})
    await mw(ctx({ 'cf-connecting-ip': '1.1.1.1' }, kv), next)
    await mw(ctx({ 'cf-connecting-ip': '2.2.2.2' }, kv), next)
    expect(next).toHaveBeenCalledTimes(2)
  })

  it('never breaks the request when KV throws', async () => {
    const next = vi.fn(async () => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const broken = { get: async () => { throw new Error('KV down') }, put: async () => {} }
    await rateLimit({ max: 1, windowMs: 1000, keyPrefix: 'login' })(
      ctx({ 'cf-connecting-ip': '1.2.3.4' }, broken),
      next
    )
    expect(next).toHaveBeenCalledTimes(1)
  })
})
