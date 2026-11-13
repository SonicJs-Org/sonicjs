// @ts-nocheck
import { describe, it, expect, afterEach } from 'vitest'
import { createSonicJSApp } from '../../../app'
import { resetHookSystem } from '../../../plugins/hooks/hook-system-singleton'
import { RAW } from '../../../utils/request-trace/traced-d1'

afterEach(() => resetHookSystem())

const stubEnv = () => ({
  DB: { prepare: () => ({ bind() { return this }, all: async () => ({ results: [] }), first: async () => null, run: async () => ({}) }), batch: async () => [] },
  CACHE_KV: { get: async () => null, put: async () => {}, delete: async () => {}, list: async () => ({ keys: [] }) },
})

describe('app.ts query-trace wiring', () => {
  it('cron-first: boot() seeds plugins with proxied bindings', async () => {
    let seen: any
    const app = createSonicJSApp({ plugins: { register: [{ name: 'cap', version: '0.0.0', onBoot: async (ctx: any) => { seen = ctx.env } }] } })
    const raw = stubEnv()
    await app.boot(raw)
    expect(seen.DB[RAW]).toBe(raw.DB)
    expect(seen.CACHE_KV[RAW]).toBe(raw.CACHE_KV)
  })

  it('disableAll: boot does not wrap, middleware not mounted', async () => {
    const app = createSonicJSApp({ plugins: { disableAll: true } })
    const raw = stubEnv()
    await app.boot(raw)
    const res = await app.request('/health', {}, raw)
    expect(res.headers.get('server-timing')).toBeNull()
    expect(raw.DB[RAW]).toBeUndefined()
  })
})
