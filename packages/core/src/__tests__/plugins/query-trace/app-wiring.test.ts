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

  it('request handlers see wrapped bindings by default, and the raw bindings under disableAll', async () => {
    const capture = async (disableAll: boolean) => {
      let seen: any
      const app = createSonicJSApp({
        plugins: { disableAll },
        middleware: { beforeAuth: [async (c: any) => { seen = c.env; return c.text('captured') }] },
      })
      const raw = stubEnv()
      await app.boot(raw)
      const res = await app.request('/admin/anything', {}, raw)
      expect(await res.text()).toBe('captured') // the capturing middleware really ran
      return { seen, raw }
    }
    const on = await capture(false)
    expect(on.seen.DB).not.toBe(on.raw.DB)
    expect(on.seen.DB[RAW]).toBe(on.raw.DB)
    expect(on.seen.CACHE_KV[RAW]).toBe(on.raw.CACHE_KV)
    const off = await capture(true)
    expect(off.seen.DB).toBe(off.raw.DB)
    expect(off.seen.CACHE_KV).toBe(off.raw.CACHE_KV)
  })
})
