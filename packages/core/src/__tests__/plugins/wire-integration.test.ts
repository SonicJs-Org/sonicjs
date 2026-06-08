/**
 * Integration tests for live plugin wiring through the app factory.
 *
 * Verifies that constructing an app and serving one request triggers the lazy,
 * once-guarded wiring pass: plugin hooks get subscribed to the app's hook system
 * (published as the singleton) and plugin `onBoot` runs.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { Hono } from 'hono'
import { createSonicJSApp } from '../../app'
import type { Plugin } from '../../plugins/types'
import {
  getHookSystem,
  hasHookSystem,
  resetHookSystem,
} from '../../plugins/hooks/hook-system-singleton'
import { createTypedHooks } from '../../plugins/hooks/typed-hooks'

afterEach(() => {
  resetHookSystem()
})

/** A plugin that records when its hook and onBoot fire. */
function makeObservablePlugin(state: { booted: boolean; hookRan: boolean }): Plugin {
  return {
    name: 'observable-plugin',
    version: '1.0.0',
    hooks: [
      {
        name: 'content:create',
        handler: async (data: any) => {
          state.hookRan = true
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

    // The subscribed hook fires when the event is dispatched on the singleton.
    await createTypedHooks(getHookSystem()).dispatch('content:create', {
      collection: 'posts',
      data: {},
    })
    expect(state.hookRan).toBe(true)
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
    expect(getHookSystem().getHooks?.('content:create') ?? []).toHaveLength(0)
  })
})
