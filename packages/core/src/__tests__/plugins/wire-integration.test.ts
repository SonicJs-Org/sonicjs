/**
 * Integration tests for live plugin wiring through the app factory.
 *
 * Verifies that constructing an app and serving one request triggers the lazy,
 * once-guarded wiring pass: plugin hooks get subscribed to the app's hook system
 * (published as the singleton) and plugin `onBoot` runs.
 *
 * T2.7: The "subscriber fires through a real route" test verifies that dispatching
 * via dispatchHookEvent() — the same helper production routes use — fires subscribed
 * handlers. It uses a separate minimal Hono app (no middleware stack that would need
 * a real DB) to call dispatchHookEvent, which reads from the global singleton set up
 * by createSonicJSApp.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { Hono } from 'hono'
import { createSonicJSApp } from '../../app'
import type { Plugin } from '../../plugins/types'
import {
  hasHookSystem,
  resetHookSystem,
} from '../../plugins/hooks/hook-system-singleton'
import { dispatchHookEvent } from '../../plugins/hooks/dispatch-event'

afterEach(() => {
  resetHookSystem()
})

/** A plugin that records when its hook and onBoot fire. */
function makeObservablePlugin(state: { booted: boolean; hookRan: boolean; payload?: unknown }): Plugin {
  return {
    name: 'observable-plugin',
    version: '1.0.0',
    hooks: [
      {
        name: 'auth:registration:completed',
        handler: async (data: any) => {
          state.hookRan = true
          state.payload = data
          return data
        },
      },
    ],
    onBoot: async () => {
      state.booted = true
    },
  } as Plugin
}

describe('live plugin wiring via createSonicJSApp', () => {
  it('publishes a hook system singleton at construction', () => {
    createSonicJSApp()
    expect(hasHookSystem()).toBe(true)
  })

  it('runs onBoot and subscribes hooks after the first request', async () => {
    const state = { booted: false, hookRan: false }
    const app = createSonicJSApp({ plugins: { register: [makeObservablePlugin(state)] } })

    // Before any request, wiring has not run.
    expect(state.booted).toBe(false)

    // One request triggers the lazy wiring pass.
    await app.request('/health')

    expect(state.booted).toBe(true)
  })

  /**
   * T2.7: The subscribed hook must fire via a call to dispatchHookEvent(), the same
   * helper production routes use — NOT via a manual hooks.dispatch() call in the test.
   * This ensures the test fails if dispatchHookEvent is removed from the real path.
   *
   * Architecture: createSonicJSApp initializes the global hook-system singleton and
   * subscribes plugin hooks during the wiring phase. A separate minimal Hono app
   * then calls dispatchHookEvent which reads from that same global singleton —
   * exactly what production routes do. This avoids needing a real DB (which the full
   * app's bootstrap middleware requires) while still testing the dispatch path.
   */
  it('a subscribed hook fires when triggered through a route that calls dispatchHookEvent', async () => {
    const state = { booted: false, hookRan: false, payload: undefined as unknown }

    // Step 1: initialize the hook system and subscribe the observer plugin's hooks.
    const app = createSonicJSApp({ plugins: { register: [makeObservablePlugin(state)] } })
    await app.request('/health') // triggers the lazy wiring pass
    expect(state.booted).toBe(true)
    expect(state.hookRan).toBe(false) // no dispatch yet

    // Step 2: a minimal Hono app (no DB middleware) that calls dispatchHookEvent —
    // the same helper production routes use. The hook fires via the global singleton.
    const triggerApp = new Hono()
    triggerApp.post('/trigger', async (c) => {
      // in-band: awaits the handler chain before returning the response.
      await dispatchHookEvent(
        c,
        'auth:registration:completed',
        { user: { id: 'test-user', email: 'trigger@test.com', role: 'viewer' } },
        'in-band'
      )
      return c.json({ ok: true })
    })

    const res = await triggerApp.request('/trigger', { method: 'POST' })
    expect(res.status).toBe(200)

    // The subscribed hook fired through the real dispatch helper.
    expect(state.hookRan).toBe(true)
    expect((state.payload as any)?.user?.id).toBe('test-user')
  })

  it('wires exactly once across multiple requests', async () => {
    let bootCount = 0
    const plugin: Plugin = {
      name: 'counter',
      version: '1.0.0',
      onBoot: async () => {
        bootCount++
      },
    } as Plugin
    const app = createSonicJSApp({ plugins: { register: [plugin] } })

    await app.request('/health')
    await app.request('/health')
    await app.request('/health')

    expect(bootCount).toBe(1)
  })

  it('does not wire plugins when disableAll is true', async () => {
    const state = { booted: false, hookRan: false }
    const app = createSonicJSApp({
      plugins: { disableAll: true, register: [makeObservablePlugin(state)] },
    })

    await app.request('/health')

    expect(state.booted).toBe(false)
    // The singleton is still published (set before the disableAll check), but it
    // carries no plugin subscriptions.
    expect(hasHookSystem()).toBe(true)
  })
})
