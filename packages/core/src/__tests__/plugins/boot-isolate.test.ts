/**
 * Tests for T3.2 — bootIsolate extraction, and T3.3 — scheduled() handler wiring.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createSonicJSApp } from '../../app'
import { createScheduledHandler } from '../../plugins/cron'
import { getHookSystem, hasHookSystem, resetHookSystem, getTypedHooks } from '../../plugins/hooks/hook-system-singleton'
import type { Plugin } from '../../plugins/types'

afterEach(() => {
  resetHookSystem()
})

// Minimal fake env (no D1 needed — bootstrap degrades gracefully)
const fakeEnv = {} as Record<string, unknown>

describe('SonicJSApp.boot (T3.2 — bootIsolate)', () => {
  it('is exposed as a function on the returned app', () => {
    const app = createSonicJSApp()
    expect(typeof app.boot).toBe('function')
  })

  it('calling boot() initializes the hook system (wires plugins)', async () => {
    let booted = false
    const plugin: Plugin = {
      name: 'test-plugin',
      version: '0.0.0',
      onBoot: async () => { booted = true },
    } as Plugin

    const app = createSonicJSApp({ plugins: { register: [plugin] } })

    expect(booted).toBe(false)
    // Call boot directly (simulates cron-first cold isolate)
    await app.boot(fakeEnv)
    expect(booted).toBe(true)
  })

  it('boot() is idempotent — calling twice only boots once', async () => {
    let bootCount = 0
    const plugin: Plugin = {
      name: 'counter',
      version: '0.0.0',
      onBoot: async () => { bootCount++ },
    } as Plugin

    const app = createSonicJSApp({ plugins: { register: [plugin] } })
    await app.boot(fakeEnv)
    await app.boot(fakeEnv)
    await app.boot(fakeEnv)

    expect(bootCount).toBe(1)
  })

  it('boot() and the HTTP middleware share the same once-guard', async () => {
    let bootCount = 0
    const plugin: Plugin = {
      name: 'counter',
      version: '0.0.0',
      onBoot: async () => { bootCount++ },
    } as Plugin

    const app = createSonicJSApp({ plugins: { register: [plugin] } })

    // First: call boot directly (cron path)
    await app.boot(fakeEnv)
    expect(bootCount).toBe(1)

    // Then: HTTP request also tries to boot — should be a no-op
    await app.request('/health')
    expect(bootCount).toBe(1)
  })

  it('boot() is a no-op when disableAll is true', async () => {
    let booted = false
    const plugin: Plugin = {
      name: 'test-plugin',
      version: '0.0.0',
      onBoot: async () => { booted = true },
    } as Plugin

    const app = createSonicJSApp({ plugins: { disableAll: true, register: [plugin] } })
    await app.boot(fakeEnv)
    expect(booted).toBe(false)
  })
})

describe('createScheduledHandler with boot option (T3.3)', () => {
  it('calls boot() before dispatching so cron-first isolate has a wired hook bus', async () => {
    let hookRan = false
    const plugin: Plugin = {
      name: 'cron-observer',
      version: '0.0.0',
      hooks: [{
        name: 'auth:registration:completed',
        handler: async (d: any) => { hookRan = true; return d },
      }],
      onBoot: async () => {},
    } as Plugin

    const app = createSonicJSApp({ plugins: { register: [plugin] } })

    // No HTTP request has been made — hook system not yet wired.
    // The scheduled handler must call boot() to wire it.
    const handler = createScheduledHandler({
      plugins: () => config.plugins?.register ?? [],
      getHooks: getHookSystem,
      boot: app.boot,
    })
    const config = { plugins: { register: [plugin] } }

    await handler({ cron: '*/15 * * * *', scheduledTime: 0 }, fakeEnv)

    // Boot ran, hook system is live. Dispatch a test event to verify.
    await getTypedHooks().dispatch('auth:registration:completed', { user: { id: 'u', email: 'a@b.com' } })
    expect(hookRan).toBe(true)
  })

  it('skips dispatch when disabled is true', async () => {
    const app = createSonicJSApp()
    const handler = createScheduledHandler({
      plugins: [],
      getHooks: getHookSystem,
      boot: app.boot,
      disabled: true,
    })

    const result = await handler({ cron: '* * * * *', scheduledTime: 0 }, fakeEnv)
    expect(result.invoked).toHaveLength(0)
    expect(result.unmatched).toBe(true)
  })

  it('handler result is unmatched when no plugins declare the fired schedule', async () => {
    const app = createSonicJSApp()
    await app.boot(fakeEnv) // pre-boot

    const handler = createScheduledHandler({
      plugins: [],
      getHooks: getHookSystem,
      boot: app.boot,
    })

    const result = await handler({ cron: '0 0 * * *', scheduledTime: 0 }, fakeEnv)
    expect(result.unmatched).toBe(true)
    expect(result.invoked).toHaveLength(0)
  })
})
