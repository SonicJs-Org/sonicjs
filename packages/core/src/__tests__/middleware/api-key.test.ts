import { describe, it, expect, beforeEach, vi } from 'vitest'
import { hashApiKey, VALID_SCOPES, requireApiKey, optionalApiKey } from '../../middleware/api-key'
import type { ApiKeyContext } from '../../middleware/api-key'
import { Context, Next } from 'hono'

// ────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────

/** Build a mock D1 that returns `row` for any .first() call. */
function mockDb(row: Record<string, any> | null) {
  return {
    prepare: vi.fn().mockReturnValue({
      bind: vi.fn().mockReturnValue({
        first: vi.fn().mockResolvedValue(row),
        run: vi.fn().mockResolvedValue({}),
      }),
    }),
  }
}

/** Build a mock KV (cache miss by default). */
function mockKv(cached: any = null) {
  return {
    get: vi.fn().mockResolvedValue(cached),
    put: vi.fn().mockResolvedValue(undefined),
    delete: vi.fn().mockResolvedValue(undefined),
  }
}

/** A valid, non-expired token row from D1. */
function validTokenRow(overrides: Partial<Record<string, any>> = {}) {
  return {
    id: 'key-1',
    name: 'Test Key',
    user_id: 'user-1',
    permissions: JSON.stringify(['search:read', 'search:write']),
    expires_at: null,
    last_used_at: null,
    ...overrides,
  }
}

// ────────────────────────────────────────────────────────────────
// hashApiKey — SHA-256 correctness
// ────────────────────────────────────────────────────────────────

describe('hashApiKey', () => {
  it('should produce a 64-character lowercase hex string', async () => {
    const hash = await hashApiKey('sk_live_abc123')
    expect(hash).toMatch(/^[a-f0-9]{64}$/)
  })

  it('should be deterministic (same input → same output)', async () => {
    const a = await hashApiKey('sk_live_test')
    const b = await hashApiKey('sk_live_test')
    expect(a).toBe(b)
  })

  it('should produce different hashes for different inputs', async () => {
    const a = await hashApiKey('sk_live_token_one')
    const b = await hashApiKey('sk_live_token_two')
    expect(a).not.toBe(b)
  })
})

// ────────────────────────────────────────────────────────────────
// Token format validation (sk_live_ prefix, length, hex chars)
// ────────────────────────────────────────────────────────────────

describe('token format', () => {
  it('generated tokens match sk_live_ + 64 hex chars', () => {
    // Simulate the token generation logic from admin-api-keys.ts
    const randomBytes = new Uint8Array(32)
    crypto.getRandomValues(randomBytes)
    const hex = Array.from(randomBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    const token = `sk_live_${hex}`

    expect(token).toMatch(/^sk_live_[a-f0-9]{64}$/)
    expect(token.length).toBe(72) // 8 prefix + 64 hex
  })
})

// ────────────────────────────────────────────────────────────────
// VALID_SCOPES
// ────────────────────────────────────────────────────────────────

describe('VALID_SCOPES', () => {
  it('contains exactly the three search scopes', () => {
    expect(VALID_SCOPES).toEqual(['search:read', 'search:write', 'search:analytics'])
  })
})

// ────────────────────────────────────────────────────────────────
// requireApiKey middleware
// ────────────────────────────────────────────────────────────────

describe('requireApiKey middleware', () => {
  let mockNext: Next
  const TOKEN = 'sk_live_' + 'a'.repeat(64)

  beforeEach(() => {
    mockNext = vi.fn()
  })

  function buildContext(opts: {
    apiKeyHeader?: string
    enforce?: boolean
    dbRow?: Record<string, any> | null
    kvCached?: any
  }) {
    const kv = mockKv(opts.kvCached ?? null)
    const db = mockDb(opts.dbRow ?? null)

    return {
      ctx: {
        req: {
          header: vi.fn().mockImplementation((name: string) => {
            if (name === 'X-API-Key') return opts.apiKeyHeader ?? undefined
            return undefined
          }),
        },
        env: {
          DB: db,
          CACHE_KV: kv,
          REQUIRE_API_KEY: opts.enforce ? 'true' : undefined,
        },
        set: vi.fn(),
        get: vi.fn(),
        json: vi.fn().mockImplementation((body: any, status?: number) => ({ body, status })),
        executionCtx: { waitUntil: vi.fn() },
      } as unknown as Context,
      kv,
      db,
    }
  }

  it('valid key with matching scope — calls next()', async () => {
    const hash = await hashApiKey(TOKEN)
    const { ctx } = buildContext({
      apiKeyHeader: TOKEN,
      dbRow: validTokenRow(),
    })

    const mw = requireApiKey('search:read')
    await mw(ctx, mockNext)

    expect(mockNext).toHaveBeenCalled()
    expect(ctx.set).toHaveBeenCalledWith('apiKey', expect.objectContaining({
      id: 'key-1',
      scopes: ['search:read', 'search:write'],
    }))
  })

  it('valid key with wrong scope — returns 403', async () => {
    const { ctx } = buildContext({
      apiKeyHeader: TOKEN,
      dbRow: validTokenRow({ permissions: JSON.stringify(['search:write']) }),
    })

    const mw = requireApiKey('search:read')
    const result = await mw(ctx, mockNext)

    expect(mockNext).not.toHaveBeenCalled()
    expect(ctx.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('Insufficient scope') }),
      403
    )
  })

  it('no key + REQUIRE_API_KEY=true — returns 401', async () => {
    const { ctx } = buildContext({ enforce: true })

    const mw = requireApiKey('search:read')
    await mw(ctx, mockNext)

    expect(mockNext).not.toHaveBeenCalled()
    expect(ctx.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('API key required') }),
      401
    )
  })

  it('no key + non-enforced (default) — passes through', async () => {
    const { ctx } = buildContext({ enforce: false })

    const mw = requireApiKey('search:read')
    await mw(ctx, mockNext)

    expect(mockNext).toHaveBeenCalled()
  })
})

// ────────────────────────────────────────────────────────────────
// optionalApiKey middleware
// ────────────────────────────────────────────────────────────────

describe('optionalApiKey middleware', () => {
  let mockNext: Next
  const TOKEN = 'sk_live_' + 'b'.repeat(64)

  beforeEach(() => {
    mockNext = vi.fn()
  })

  function buildContext(opts: {
    apiKeyHeader?: string
    dbRow?: Record<string, any> | null
  }) {
    const kv = mockKv()
    const db = mockDb(opts.dbRow ?? null)
    return {
      ctx: {
        req: {
          header: vi.fn().mockImplementation((name: string) => {
            if (name === 'X-API-Key') return opts.apiKeyHeader ?? undefined
            return undefined
          }),
        },
        env: { DB: db, CACHE_KV: kv },
        set: vi.fn(),
        get: vi.fn(),
        json: vi.fn(),
        executionCtx: { waitUntil: vi.fn() },
      } as unknown as Context,
      kv,
      db,
    }
  }

  it('no header — passes through without setting apiKey', async () => {
    const { ctx } = buildContext({})

    const mw = optionalApiKey()
    await mw(ctx, mockNext)

    expect(mockNext).toHaveBeenCalled()
    expect(ctx.set).not.toHaveBeenCalled()
  })

  it('valid key — sets apiKey on context and passes through', async () => {
    const { ctx } = buildContext({
      apiKeyHeader: TOKEN,
      dbRow: validTokenRow(),
    })

    const mw = optionalApiKey()
    await mw(ctx, mockNext)

    expect(mockNext).toHaveBeenCalled()
    expect(ctx.set).toHaveBeenCalledWith('apiKey', expect.objectContaining({
      id: 'key-1',
      name: 'Test Key',
    }))
  })
})

// ────────────────────────────────────────────────────────────────
// Expiry check (expired / null / future)
// ────────────────────────────────────────────────────────────────

describe('expiry handling', () => {
  let mockNext: Next
  const TOKEN = 'sk_live_' + 'c'.repeat(64)

  beforeEach(() => {
    mockNext = vi.fn()
  })

  function buildContext(dbRow: Record<string, any> | null) {
    const kv = mockKv()
    const db = mockDb(dbRow)
    return {
      req: {
        header: vi.fn().mockImplementation((name: string) => {
          if (name === 'X-API-Key') return TOKEN
          return undefined
        }),
      },
      env: { DB: db, CACHE_KV: kv, REQUIRE_API_KEY: 'true' },
      set: vi.fn(),
      get: vi.fn(),
      json: vi.fn().mockImplementation((body: any, status?: number) => ({ body, status })),
      executionCtx: { waitUntil: vi.fn() },
    } as unknown as Context
  }

  it('expired key (ISO string in the past) — treated as invalid', async () => {
    const ctx = buildContext(
      validTokenRow({ expires_at: '2020-01-01T00:00:00Z' })
    )

    const mw = requireApiKey('search:read')
    await mw(ctx, mockNext)

    // With REQUIRE_API_KEY=true, an expired key means no valid key → 401
    expect(mockNext).not.toHaveBeenCalled()
    expect(ctx.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('API key required') }),
      401
    )
  })

  it('null expires_at — key never expires, passes through', async () => {
    const ctx = buildContext(validTokenRow({ expires_at: null }))

    const mw = requireApiKey('search:read')
    await mw(ctx, mockNext)

    expect(mockNext).toHaveBeenCalled()
  })

  it('future expires_at — key is still valid, passes through', async () => {
    const future = new Date(Date.now() + 86400000).toISOString()
    const ctx = buildContext(validTokenRow({ expires_at: future }))

    const mw = requireApiKey('search:read')
    await mw(ctx, mockNext)

    expect(mockNext).toHaveBeenCalled()
  })
})

// ────────────────────────────────────────────────────────────────
// last_used_at — waitUntil fires on valid key
// ────────────────────────────────────────────────────────────────

describe('last_used_at update', () => {
  it('calls waitUntil to update last_used_at on valid key lookup', async () => {
    const TOKEN = 'sk_live_' + 'd'.repeat(64)
    const mockNext: Next = vi.fn()
    const kv = mockKv()
    const db = mockDb(validTokenRow())
    const waitUntil = vi.fn()

    const ctx = {
      req: {
        header: vi.fn().mockImplementation((name: string) => {
          if (name === 'X-API-Key') return TOKEN
          return undefined
        }),
      },
      env: { DB: db, CACHE_KV: kv },
      set: vi.fn(),
      get: vi.fn(),
      json: vi.fn(),
      executionCtx: { waitUntil },
    } as unknown as Context

    const mw = optionalApiKey()
    await mw(ctx, mockNext)

    expect(waitUntil).toHaveBeenCalled()
  })
})
