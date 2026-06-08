import { describe, it, expect } from 'vitest'
import { HookSystemImpl } from '../../plugins/hook-system'
import {
  wireRegisteredPlugins,
  createPluginWirer,
  type WirablePlugin,
  type PluginBootContext,
} from '../../plugins/wire'

function ctx(): PluginBootContext {
  return { hooks: new HookSystemImpl() }
}

describe('wireRegisteredPlugins', () => {
  it('subscribes a plugin hook so a later dispatch reaches it', async () => {
    const c = ctx()
    let received: any
    const plugin: WirablePlugin = {
      name: 'sub',
      hooks: [{ name: 'content:create', handler: (data) => void (received = data) }],
    }

    const result = await wireRegisteredPlugins([plugin], c)
    expect(result.subscribed).toBe(1)

    await c.hooks.execute('content:create', { collection: 'posts', data: {} })
    expect(received).toEqual({ collection: 'posts', data: {} })
  })

  it('runs onBoot and reports booted plugins', async () => {
    const c = ctx()
    let booted = false
    const plugin: WirablePlugin = {
      name: 'boot',
      onBoot: async () => {
        booted = true
      },
    }
    const result = await wireRegisteredPlugins([plugin], c)
    expect(booted).toBe(true)
    expect(result.booted).toEqual(['boot'])
  })

  it('subscribes ALL hooks before running ANY onBoot', async () => {
    // Plugin B's onBoot relies on Plugin A's hook already being registered.
    const c = ctx()
    const events: string[] = []
    const a: WirablePlugin = {
      name: 'a',
      hooks: [{ name: 'content:create', handler: () => void events.push('a-hook-ran') }],
    }
    const b: WirablePlugin = {
      name: 'b',
      onBoot: async (boot) => {
        await boot.hooks.execute('content:create', { collection: 'x', data: {} })
      },
    }
    await wireRegisteredPlugins([a, b], c)
    expect(events).toEqual(['a-hook-ran'])
  })

  it('isolates a failing onBoot — other plugins still boot', async () => {
    const c = ctx()
    const order: string[] = []
    const bad: WirablePlugin = {
      name: 'bad',
      onBoot: async () => {
        throw new Error('boom')
      },
    }
    const good: WirablePlugin = {
      name: 'good',
      onBoot: async () => void order.push('good'),
    }
    const result = await wireRegisteredPlugins([bad, good], c)
    expect(order).toEqual(['good'])
    expect(result.booted).toEqual(['good'])
    expect(result.errors).toHaveLength(1)
    expect(result.errors[0]).toMatchObject({ plugin: 'bad', phase: 'onBoot' })
  })

  it('ignores null/undefined plugins and plugins with no hooks/onBoot', async () => {
    const c = ctx()
    const result = await wireRegisteredPlugins([null, undefined, { name: 'empty' }], c)
    expect(result.subscribed).toBe(0)
    expect(result.booted).toEqual([])
    expect(result.errors).toHaveLength(0)
  })

  it('records an invalid hook entry as an error without throwing', async () => {
    const c = ctx()
    const plugin: WirablePlugin = {
      name: 'badhook',
      // @ts-expect-error intentionally malformed
      hooks: [{ name: 'content:create' /* missing handler */ }],
    }
    const result = await wireRegisteredPlugins([plugin], c)
    expect(result.subscribed).toBe(0)
    expect(result.errors[0]).toMatchObject({ plugin: 'badhook', phase: 'subscribe' })
  })
})

describe('createPluginWirer (once-guard)', () => {
  it('runs the wiring exactly once across many calls', async () => {
    let bootCount = 0
    const plugin: WirablePlugin = {
      name: 'counted',
      onBoot: async () => {
        bootCount++
      },
    }
    const wire = createPluginWirer([plugin], ctx)

    // Fire many concurrent "first requests".
    const results = await Promise.all([wire(), wire(), wire(), wire()])

    expect(bootCount).toBe(1)
    // All callers get the same result object.
    expect(results[0]).toBe(results[1])
    expect(results[0]).toBe(results[3])
  })

  it('evaluates a lazy plugin list only once, at first call', async () => {
    let evaluated = 0
    const wire = createPluginWirer(
      () => {
        evaluated++
        return [{ name: 'p' }]
      },
      ctx
    )
    await wire()
    await wire()
    expect(evaluated).toBe(1)
  })
})
