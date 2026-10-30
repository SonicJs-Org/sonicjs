/**
 * Tests for the dispatchHookEvent helper and the capability-gate in wire.ts.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { dispatchHookEvent } from '../../plugins/hooks/dispatch-event'
import { wireRegisteredPlugins } from '../../plugins/wire'
import { HookSystemImpl } from '../../plugins/hook-system'
import { setHookSystem, resetHookSystem, getHookSystem } from '../../plugins/hooks/hook-system-singleton'
import { SonicCapabilityError } from '../../plugins/capabilities'
import type { WirablePlugin } from '../../plugins/wire'

afterEach(() => {
  resetHookSystem()
})

// ── helpers ───────────────────────────────────────────────────────────────────

function freshHookSystem() {
  const hs = new HookSystemImpl()
  setHookSystem(hs)
  return hs
}

// ── dispatchHookEvent ─────────────────────────────────────────────────────────

describe('dispatchHookEvent', () => {
  it('is a no-op when the hook system has not been initialized', async () => {
    // No setHookSystem() call — singleton is unset.
    const result = await dispatchHookEvent(
      null,
      'auth:registration:completed',
      { user: { id: 'u1', email: 'a@b.com' } }
    )
    expect(result).toEqual({ user: { id: 'u1', email: 'a@b.com' } })
  })

  it('fire-and-forget: returns the original payload immediately', async () => {
    const hs = freshHookSystem()
    let handlerRan = false
    hs.register('auth:registration:completed', async (d: any) => {
      handlerRan = true
      return d
    })

    const payload = { user: { id: 'u1', email: 'a@b.com', role: 'viewer' } }
    // Pass null/undefined context — no executionCtx available (test environment)
    const result = await dispatchHookEvent(null, 'auth:registration:completed', payload, 'fire-and-forget')

    // In fire-and-forget mode the call is non-blocking; we use in-band below for
    // the "handler ran" assertion since we can't reliably wait for background tasks.
    expect(result).toBe(payload) // same reference — original returned immediately
    void handlerRan // handler may or may not have run yet (background)
  })

  it('fire-and-forget: calls waitUntil when executionCtx is present on the context object', async () => {
    freshHookSystem()
    const waited: Promise<unknown>[] = []
    // Simulate a Hono context that has executionCtx with waitUntil
    const fakeHonoCtx = {
      executionCtx: { waitUntil: (p: Promise<unknown>) => { waited.push(p) } }
    }

    await dispatchHookEvent(fakeHonoCtx, 'auth:registration:completed', { user: { id: 'u1', email: 'a@b.com' } }, 'fire-and-forget')

    expect(waited).toHaveLength(1)
    await waited[0] // drain the queued promise
  })

  it('in-band: awaits the handler chain and returns mutated payload', async () => {
    const hs = freshHookSystem()
    hs.register('content:after:create', async (data: any) => {
      return { ...data, data: { ...data.data, _mutated: true } }
    })

    const payload = { collection: 'posts', data: {} }
    const result = await dispatchHookEvent(null, 'content:after:create', payload, 'in-band')

    expect((result.data as any)._mutated).toBe(true)
  })

  it('in-band: propagates CRITICAL handler errors (allows hard-cancel semantics)', async () => {
    const hs = freshHookSystem()
    // The underlying HookSystemImpl only re-throws errors whose message includes
    // 'CRITICAL'. Regular errors are swallowed (logged + continue chain). A plugin
    // that wants to hard-cancel a write should use 'CRITICAL' in the error message.
    hs.register('content:before:create', async () => {
      throw new Error('CRITICAL: access denied by plugin')
    })

    await expect(
      dispatchHookEvent(null, 'content:before:create', { collection: 'posts', data: {} }, 'in-band')
    ).rejects.toThrow('CRITICAL')
  })

  it('fire-and-forget: swallows handler errors (never rejects)', async () => {
    const hs = freshHookSystem()
    hs.register('auth:registration:completed', async () => {
      throw new Error('handler error')
    })

    await expect(
      dispatchHookEvent(null, 'auth:registration:completed', { user: { id: 'u', email: 'a@b.com' } }, 'fire-and-forget')
    ).resolves.toBeDefined()
  })
})

// ── wire.ts capability gate (T2.4) ────────────────────────────────────────────

describe('wireRegisteredPlugins capability gate', () => {
  function makeHookCtx() {
    const hs = new HookSystemImpl()
    setHookSystem(hs)
    return { hooks: hs }
  }

  it('allows a hook subscription when the required capability is declared', async () => {
    let fired = false
    const plugin: WirablePlugin = {
      name: 'gated-plugin',
      capabilities: ['hooks.content:subscribe'],
      hooks: [{ name: 'content:after:create', handler: async (d: any) => { fired = true; return d } }],
    }

    const ctx = makeHookCtx()
    const result = await wireRegisteredPlugins([plugin], ctx)

    expect(result.subscribed).toBe(1)
    expect(result.errors).toHaveLength(0)

    // Verify it actually fires.
    await getHookSystem().execute('content:after:create', { collection: 'posts', data: {} })
    expect(fired).toBe(true)
  })

  it('blocks a hook subscription and warns when the required capability is missing (non-strict)', async () => {
    const warns: string[] = []
    const origWarn = console.warn
    console.warn = (...args: any[]) => warns.push(args.join(' '))

    try {
      const plugin: WirablePlugin = {
        name: 'ungated-plugin',
        capabilities: [], // no hooks.content:subscribe
        hooks: [{ name: 'content:after:create', handler: async (d: any) => d }],
      }

      const ctx = makeHookCtx()
      const result = await wireRegisteredPlugins([plugin], ctx)

      expect(result.subscribed).toBe(0)
      expect(result.errors).toHaveLength(0) // non-strict: warn, not error
      expect(warns.some((w) => w.includes('hooks.content:subscribe'))).toBe(true)
    } finally {
      console.warn = origWarn
    }
  })

  it('captures a SonicCapabilityError in strict mode when capability is missing', async () => {
    const plugin: WirablePlugin = {
      name: 'ungated-strict-plugin',
      capabilities: [],
      hooks: [{ name: 'auth:registration:completed', handler: async (d: any) => d }],
    }

    const ctx = makeHookCtx()
    const result = await wireRegisteredPlugins([plugin], ctx, { strict: true })

    expect(result.subscribed).toBe(0)
    expect(result.errors).toHaveLength(1)
    expect(result.errors[0]!.error).toBeInstanceOf(SonicCapabilityError)
    expect((result.errors[0]!.error as SonicCapabilityError).capability).toBe('hooks.auth:subscribe')
  })

  it('old-style plugins (no capabilities field) are exempt from the gate', async () => {
    const plugin: WirablePlugin = {
      name: 'legacy-plugin',
      // capabilities is intentionally absent — old PluginBuilder pattern
      hooks: [{ name: 'content:after:create', handler: async (d: any) => d }],
    }

    const ctx = makeHookCtx()
    const result = await wireRegisteredPlugins([plugin], ctx, { strict: true })

    expect(result.subscribed).toBe(1)
    expect(result.errors).toHaveLength(0)
  })
})

// ── SonicCapabilityError.accessedApi (T2.5) ───────────────────────────────────

describe('SonicCapabilityError.accessedApi', () => {
  it('carries an optional accessedApi field', () => {
    const err = new SonicCapabilityError('email:send', 'my-plugin', 'ctx.cap.email')
    expect(err.capability).toBe('email:send')
    expect(err.plugin).toBe('my-plugin')
    expect(err.accessedApi).toBe('ctx.cap.email')
  })

  it('accessedApi is optional — existing constructor signature unchanged', () => {
    const err = new SonicCapabilityError('email:send', 'my-plugin')
    expect(err.accessedApi).toBeUndefined()
  })
})
