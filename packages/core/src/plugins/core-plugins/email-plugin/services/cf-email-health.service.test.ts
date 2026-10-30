import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { CfEmailHealthService } from './cf-email-health.service'

const MOCK_TOKEN = 'test-token'
const MOCK_ACCOUNT = 'acc-123'
const MOCK_ZONE = 'zone-456'

function makeKv(cached: unknown = null) {
  return {
    get: vi.fn(async () => cached),
    put: vi.fn(async () => undefined),
    delete: vi.fn(),
    getWithMetadata: vi.fn(),
    list: vi.fn(),
  } as unknown as KVNamespace
}

function mockFetch(responses: { ok: boolean; body: unknown }[]) {
  let call = 0
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
    const r = responses[call++] ?? { ok: false, body: {} }
    return {
      ok: r.ok,
      json: async () => r.body,
    } as Response
  })
}

beforeEach(() => { vi.useFakeTimers() })
afterEach(() => {
  vi.restoreAllMocks()
  vi.useRealTimers()
})

describe('CfEmailHealthService.getHealth()', () => {
  it('returns unconfigured when apiToken is absent', async () => {
    const svc = new CfEmailHealthService(undefined, MOCK_ACCOUNT, MOCK_ZONE, undefined)
    const result = await svc.getHealth()
    expect(result.status).toBe('unconfigured')
    expect(result.destinations).toEqual([])
    expect(result.emailRoutingEnabled).toBeNull()
  })

  it('returns unconfigured when accountId is absent', async () => {
    const svc = new CfEmailHealthService(MOCK_TOKEN, undefined, MOCK_ZONE, undefined)
    const result = await svc.getHealth()
    expect(result.status).toBe('unconfigured')
  })

  it('returns emailRoutingEnabled: null when zoneId absent but accountId present', async () => {
    mockFetch([
      { ok: true, body: { success: true, result: [{ email: 'a@b.c', verified: '2026-01-01T00:00:00Z' }] } },
    ])
    const svc = new CfEmailHealthService(MOCK_TOKEN, MOCK_ACCOUNT, undefined, undefined)
    const result = await svc.getHealth()
    expect(result.emailRoutingEnabled).toBeNull()
    expect(result.emailRoutingZone).toBeNull()
    expect(result.destinations).toHaveLength(1)
    expect(result.status).toBe('ok')
  })

  it('returns cached result when KV has a valid entry (CF API not called)', async () => {
    const fetchSpy = mockFetch([])
    const cachedHealth = {
      status: 'ok', emailRoutingEnabled: true, emailRoutingZone: 'sonicjs.com',
      destinations: [], checkedAt: Date.now(),
    }
    const kv = makeKv(cachedHealth)
    const svc = new CfEmailHealthService(MOCK_TOKEN, MOCK_ACCOUNT, MOCK_ZONE, kv)
    const result = await svc.getHealth()
    expect(result.status).toBe('ok')
    expect(result.emailRoutingZone).toBe('sonicjs.com')
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('calls CF API on KV miss and writes result to KV with 60s TTL', async () => {
    mockFetch([
      { ok: true, body: { success: true, result: { name: 'sonicjs.com', enabled: true } } },
      { ok: true, body: { success: true, result: [] } },
    ])
    const kv = makeKv(null) // cache miss
    const svc = new CfEmailHealthService(MOCK_TOKEN, MOCK_ACCOUNT, MOCK_ZONE, kv)
    await svc.getHealth()
    expect(kv.put).toHaveBeenCalledOnce()
    const [, , opts] = (kv.put as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(opts).toMatchObject({ expirationTtl: 60 })
  })

  it('returns status: error when routing CF API returns non-2xx', async () => {
    mockFetch([
      { ok: false, body: {} }, // routing call fails
      { ok: true, body: { success: true, result: [] } },
    ])
    const svc = new CfEmailHealthService(MOCK_TOKEN, MOCK_ACCOUNT, MOCK_ZONE, undefined)
    const result = await svc.getHealth()
    expect(result.status).toBe('error')
  })

  it('returns status: error when CF API returns HTTP 200 with success: false', async () => {
    mockFetch([
      { ok: true, body: { success: false, result: null, errors: [{ message: 'Forbidden' }] } },
      { ok: true, body: { success: true, result: [] } },
    ])
    const svc = new CfEmailHealthService(MOCK_TOKEN, MOCK_ACCOUNT, MOCK_ZONE, undefined)
    const result = await svc.getHealth()
    expect(result.status).toBe('error')
  })

  it('correctly maps verified: null → verified: false on destination addresses', async () => {
    mockFetch([
      { ok: true, body: { success: true, result: { name: 'sonicjs.com', enabled: true } } },
      {
        ok: true, body: {
          success: true, result: [
            { email: 'verified@example.com', verified: '2026-01-01T00:00:00Z' },
            { email: 'unverified@example.com', verified: null },
          ],
        },
      },
    ])
    const svc = new CfEmailHealthService(MOCK_TOKEN, MOCK_ACCOUNT, MOCK_ZONE, undefined)
    const result = await svc.getHealth()
    const v = result.destinations.find(d => d.email === 'verified@example.com')
    const u = result.destinations.find(d => d.email === 'unverified@example.com')
    expect(v?.verified).toBe(true)
    expect(u?.verified).toBe(false)
  })

  it('returns status: error when destinations CF API returns non-2xx', async () => {
    mockFetch([
      { ok: true, body: { success: true, result: { name: 'sonicjs.com', enabled: true } } },
      { ok: false, body: {} }, // destinations 403
    ])
    const svc = new CfEmailHealthService(MOCK_TOKEN, MOCK_ACCOUNT, MOCK_ZONE, undefined)
    const result = await svc.getHealth()
    expect(result.status).toBe('error')
    expect(result.destinations).toEqual([])
  })

  it('returns status: error when destinations CF API returns success: false', async () => {
    mockFetch([
      { ok: true, body: { success: true, result: { name: 'sonicjs.com', enabled: true } } },
      { ok: true, body: { success: false, result: null, errors: [{ message: 'Forbidden' }] } },
    ])
    const svc = new CfEmailHealthService(MOCK_TOKEN, MOCK_ACCOUNT, MOCK_ZONE, undefined)
    const result = await svc.getHealth()
    expect(result.status).toBe('error')
    expect(result.destinations).toEqual([])
  })

  it('never throws — unexpected error returns status: error, not an exception', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network down'))
    const svc = new CfEmailHealthService(MOCK_TOKEN, MOCK_ACCOUNT, MOCK_ZONE, undefined)
    await expect(svc.getHealth()).resolves.toMatchObject({ status: 'error' })
  })
})
