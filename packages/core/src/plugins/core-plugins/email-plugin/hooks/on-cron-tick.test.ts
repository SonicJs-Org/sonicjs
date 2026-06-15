import { describe, it, expect, vi, beforeEach } from 'vitest'
import { onCronTick } from './on-cron-tick'
import type { SonicHookContext } from '../../../sdk/types'

interface MockEnv {
  DB?: unknown
  CF_ZONE_ID?: string
  EMAIL_API_TOKEN?: string
}

function makeCtx(env: MockEnv): SonicHookContext {
  return {
    env: env as never,
    pluginId: 'email',
    plugins: { byId: new Map(), ordered: [] },
  } as unknown as SonicHookContext
}

// Well-known empty envelope shape for the zone-scoped dataset (the only
// outbound-email GraphQL field that exists in CF's schema). Used by every
// test that wants the GraphQL call to succeed-but-return-nothing.
function emptyZoneEnvelope() {
  return { data: { viewer: { zones: [{ emailSendingAdaptive: [] }] } } }
}

function zoneEnvelope(rows: unknown[]) {
  return { data: { viewer: { zones: [{ emailSendingAdaptive: rows }] } } }
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('onCronTick — hookFamily filter', () => {
  it('returns early for unrelated cron families (does not check credentials)', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const ctx = makeCtx({}) // no credentials, no DB

    await onCronTick(ctx, {
      type: 'cron:tick',
      schedule: '*/5 * * * *',
      hookFamily: 'some-other-plugin-cron',
      triggeredAt: 1700000000000,
    })

    expect(warn).not.toHaveBeenCalled()
  })
})

describe('onCronTick — credential check', () => {
  it('logs and skips when CF_ZONE_ID is missing', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const ctx = makeCtx({ DB: {}, EMAIL_API_TOKEN: 'tok' })

    await onCronTick(ctx, {
      type: 'cron:tick',
      schedule: '*/5 * * * *',
      hookFamily: 'email-reconciliation',
      triggeredAt: 0,
    })

    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('CF GraphQL credentials missing'),
      expect.objectContaining({ haveZoneId: false, haveApiToken: true }),
    )
  })

  it('logs and skips when EMAIL_API_TOKEN is missing', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const ctx = makeCtx({ DB: {}, CF_ZONE_ID: 'zone' })

    await onCronTick(ctx, {
      type: 'cron:tick',
      schedule: '*/5 * * * *',
      hookFamily: 'email-reconciliation',
      triggeredAt: 0,
    })

    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('CF GraphQL credentials missing'),
      expect.objectContaining({ haveZoneId: true, haveApiToken: false }),
    )
  })

  it('does not throw when both credentials are missing (defensive)', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const ctx = makeCtx({ DB: {} })

    await expect(
      onCronTick(ctx, {
        type: 'cron:tick',
        schedule: '*/5 * * * *',
        hookFamily: 'email-reconciliation',
        triggeredAt: 0,
      }),
    ).resolves.toBeUndefined()
  })
})

function makeDb(): D1Database {
  return {
    prepare: vi.fn(() => ({
      bind: vi.fn(() => ({
        run: vi.fn(async () => ({})),
        first: vi.fn(async () => null),
        all: vi.fn(async () => ({ results: [] })),
      })),
    })),
  } as unknown as D1Database
}

describe('onCronTick — happy path (credentials present)', () => {
  it('no_rows: logs the no_rows outcome when GraphQL returns empty array (#701 observability)', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'warn').mockImplementation(() => {})

    const origFetch = globalThis.fetch
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify(emptyZoneEnvelope()), { status: 200 }),
    ) as never

    const ctx = makeCtx({ DB: {} as unknown, CF_ZONE_ID: 'zone', EMAIL_API_TOKEN: 'tok' })
    await onCronTick(ctx, { type: 'cron:tick', schedule: '*/5 * * * *', hookFamily: 'email-reconciliation', triggeredAt: 1700000000000 })

    // Pre-#701: this outcome was silently swallowed — making "cron working but
    // CF returned 0 rows" indistinguishable from "cron never fired" in worker logs.
    // The on-cron-tick handler now logs no_rows explicitly. (The CfGraphqlClient
    // also logs an envelope-shape diagnostic when it returns 0 rows — that's a
    // separate, additive log line, hence toHaveBeenCalled rather than calledOnce.)
    expect(log).toHaveBeenCalled()
    const calls = log.mock.calls.map(c => c[0] as string)
    expect(calls.some(s => s.includes('reconciliation cron: no_rows'))).toBe(true)

    globalThis.fetch = origFetch
  })

  it('ok: logs reconciliation result when rows are returned and updated', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'warn').mockImplementation(() => {})

    const origFetch = globalThis.fetch
    globalThis.fetch = vi.fn(async () =>
      new Response(
        JSON.stringify(zoneEnvelope([{ messageId: 'cf-1', status: 'delivered' }])),
        { status: 200 },
      ),
    ) as never

    const ctx = makeCtx({ DB: makeDb(), CF_ZONE_ID: 'zone', EMAIL_API_TOKEN: 'tok' })
    await onCronTick(ctx, { type: 'cron:tick', schedule: '*/5 * * * *', hookFamily: 'email-reconciliation', triggeredAt: 1700000000000 })

    expect(log).toHaveBeenCalledWith(
      expect.stringContaining('reconciliation cron: ok'),
      expect.objectContaining({ graphqlRowCount: 1 }),
    )
    globalThis.fetch = origFetch
  })

  it('graphql_error: logs warning when GraphQL request fails (non-200)', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const origFetch = globalThis.fetch
    globalThis.fetch = vi.fn(async () => new Response('Internal Server Error', { status: 500 })) as never

    const ctx = makeCtx({ DB: makeDb(), CF_ZONE_ID: 'zone', EMAIL_API_TOKEN: 'tok' })
    await onCronTick(ctx, { type: 'cron:tick', schedule: '*/5 * * * *', hookFamily: 'email-reconciliation', triggeredAt: 0 })

    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('GraphQL error'),
      expect.objectContaining({ error: expect.stringContaining('HTTP 500') }),
    )
    globalThis.fetch = origFetch
  })
})

describe('onCronTick — D1 settings fallback', () => {
  // Note: D1 fallback for the *token* (cfEmailApiToken) is retained. D1
  // fallback for *zoneId* was dropped because EmailSettings doesn't carry
  // a cfZoneId field today, and zone IDs are normally provisioned per-env
  // at deploy time via wrangler secret put CF_ZONE_ID. If per-tenant zone
  // overrides become needed, add cfZoneId to EmailSettings as a follow-up
  // and add a matching fallback here.

  it('reads cfEmailApiToken from D1 when env.EMAIL_API_TOKEN is absent and logs debug', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const debug = vi.spyOn(console, 'debug').mockImplementation(() => {})
    const db = {
      prepare: vi.fn(() => ({
        first: vi.fn(async () => ({ settings: JSON.stringify({ cfEmailApiToken: 'tok-d1' }) })),
      })),
    } as unknown as D1Database
    const ctx = makeCtx({ DB: db, CF_ZONE_ID: 'zone' }) // EMAIL_API_TOKEN absent
    await onCronTick(ctx, { type: 'cron:tick', schedule: '*/5 * * * *', hookFamily: 'email-reconciliation', triggeredAt: 0 })
    expect(debug).toHaveBeenCalledWith(expect.stringContaining('EMAIL_API_TOKEN read from D1'))
  })
})
