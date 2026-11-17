import { describe, it, expect } from 'vitest'
import { Hono } from 'hono'
import { HookSystemImpl } from '../../../plugins/hook-system'
import { registerPlugins, type RegisterablePlugin } from '../../../plugins/sdk/register-plugins'

/**
 * Regression tests for #1194 as it applies to the plugin SDK's own cached
 * boot promise (`registerPlugins().boot()`), which has the identical
 * cold-isolate cross-request-promise-drop bug as `createPluginWirer` in
 * `wire.ts` — see that file's doc comment for the full root-cause writeup.
 */
describe('registerPlugins().boot() — executionCtx lifetime extension', () => {
  function registry(plugin: RegisterablePlugin) {
    const app = new Hono()
    return registerPlugins(app, [plugin], { hookSystem: new HookSystemImpl() })
  }

  it('extends only the creating boot() call’s executionCtx, not later concurrent callers’', async () => {
    let release: () => void = () => {}
    const pending = new Promise<void>((resolve) => { release = resolve })
    const plugin: RegisterablePlugin = {
      id: 'p',
      version: '1.0.0',
      onBoot: async () => { await pending },
    }
    const reg = registry(plugin)

    const callers: string[] = []
    const registered: Promise<unknown>[] = []
    const ctxA = { waitUntil: (p: Promise<unknown>) => { callers.push('A'); registered.push(p) } }
    const ctxB = { waitUntil: (p: Promise<unknown>) => { callers.push('B'); registered.push(p) } }

    const first = reg.boot({}, ctxA)
    const second = reg.boot({}, ctxB)

    expect(first).toBe(second)
    // Only the creator's (first) executionCtx.waitUntil is used — but it's
    // called twice: once for the main wire promise, once for the background
    // DB-reflection work.
    expect(callers).toEqual(['A', 'A'])
    expect(registered).toHaveLength(2)

    release()
    await first
  })

  it('still boots correctly with no executionCtx at all (back-compat)', async () => {
    const plugin: RegisterablePlugin = { id: 'p', version: '1.0.0' }
    const reg = registry(plugin)
    await expect(reg.boot()).resolves.toMatchObject({ booted: [] })
    await expect(reg.boot({})).resolves.toMatchObject({ booted: [] })
  })
})
