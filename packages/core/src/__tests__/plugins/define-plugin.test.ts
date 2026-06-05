import { describe, it, expect, vi, afterEach } from 'vitest'
import { Hono } from 'hono'
import { definePlugin, isDefinedPlugin } from '../../plugins/sdk/define-plugin'
import { registerPluginRoutes } from '../../plugins/mount'
import { wireRegisteredPlugins, type PluginBootContext } from '../../plugins/wire'
import { dispatchCronTick } from '../../plugins/cron'
import { HookSystemImpl } from '../../plugins/hook-system'
import { SonicCapabilityError } from '../../plugins/capabilities'
import type { EmailService } from '../../services/email/email-service'

afterEach(() => vi.restoreAllMocks())

// ── Type-level: const-generic capability narrowing (tsc-validated, never run) ──
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function __capabilityNarrowing(): void {
  // Declaring email:send narrows ctx.cap.email to EmailService.
  definePlugin({
    id: 'with-email',
    version: '1.0.0',
    capabilities: ['email:send'],
    onBoot(ctx) {
      const svc: EmailService = ctx.cap.email // ✓
      void svc
    },
  })

  // Declaring a different capability leaves ctx.cap.email un-granted (branded),
  // so using it as an EmailService is a compile error.
  definePlugin({
    id: 'other-cap',
    version: '1.0.0',
    capabilities: ['cache:read'],
    onBoot(ctx) {
      // @ts-expect-error — email:send not declared; ctx.cap.email is not EmailService
      const svc: EmailService = ctx.cap.email
      void svc
    },
  })

  // Declaring NO capabilities grants nothing.
  definePlugin({
    id: 'no-caps',
    version: '1.0.0',
    onBoot(ctx) {
      // @ts-expect-error — no capabilities declared at all
      const svc: EmailService = ctx.cap.email
      void svc
    },
  })

  // Declarative hooks map: per-event payload narrowing + unknown-event rejection.
  definePlugin({
    id: 'decl',
    version: '1.0.0',
    hooks: {
      'content:after:create': (payload) => {
        const c: string = payload.collection // ✓ narrowed to ContentEventPayload
        void c
      },
      'auth:registration:completed': (payload) => {
        const id: string = payload.user.id // ✓ narrowed to the auth payload
        void id
      },
      // @ts-expect-error — 'not:an:event' is not a catalog event name
      'not:an:event': () => {},
    },
  })
}

function bootCtx(extra: Record<string, unknown> = {}): PluginBootContext {
  return { hooks: new HookSystemImpl(), ...extra }
}

describe('definePlugin — shape', () => {
  it('normalizes id → name and carries metadata + the v3 marker', () => {
    const p = definePlugin({ id: 'my-plugin', version: '1.2.3', description: 'd', dependencies: ['auth'] })
    expect(p.name).toBe('my-plugin')
    expect(p.id).toBe('my-plugin')
    expect(p.version).toBe('1.2.3')
    expect(p.description).toBe('d')
    expect(p.dependencies).toEqual(['auth'])
    expect(p.capabilities).toEqual([])
    expect(isDefinedPlugin(p)).toBe(true)
    expect(isDefinedPlugin({ name: 'x' })).toBe(false)
  })

  it('requires id and version', () => {
    // @ts-expect-error missing id
    expect(() => definePlugin({ version: '1.0.0' })).toThrow(/`id` is required/)
    // @ts-expect-error missing version
    expect(() => definePlugin({ id: 'x' })).toThrow(/`version` is required/)
  })

  it('warns on unknown capabilities and drops them (keeps the known ones)', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const p = definePlugin({ id: 'x', version: '1.0.0', capabilities: ['email:send', 'totally:fake' as any] })
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('unknown capabilities: totally:fake'))
    // An unknown capability is NOT a granted capability — dropped, not stored.
    expect(p.capabilities).toEqual(['email:send'])
  })

  it('normalizes deprecated/cross-fork capability spellings without warning', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const p = definePlugin({ id: 'x', version: '1.0.0', capabilities: ['storage:write' as any, 'hooks.auth:register' as any] })
    expect(p.capabilities).toEqual(['media:write', 'hooks.auth:subscribe'])
    expect(warn).not.toHaveBeenCalled()
  })
})

describe('definePlugin — mounts like any plugin', () => {
  it('declarative routes mount via registerPluginRoutes', async () => {
    const sub = new Hono().get('/', (c) => c.text('defined-ok'))
    const p = definePlugin({ id: 'routed', version: '1.0.0', routes: [{ path: '/api/defined', handler: sub }] })

    const app = new Hono()
    registerPluginRoutes(app, [p])

    expect(await (await app.request('/api/defined')).text()).toBe('defined-ok')
  })

  it('synchronous register(app) is invoked at mount', async () => {
    const p = definePlugin({
      id: 'imp',
      version: '1.0.0',
      register(app) {
        app.route('/imp', new Hono().get('/', (c) => c.text('imp-ok')))
      },
    })
    const app = new Hono()
    registerPluginRoutes(app, [p])
    expect(await (await app.request('/imp')).text()).toBe('imp-ok')
  })
})

describe('definePlugin — onBoot enriched context', () => {
  it('subscribes a typed hook that fires on dispatch through the live system', async () => {
    let seenEmail = ''
    const p = definePlugin({
      id: 'welcome',
      version: '1.0.0',
      capabilities: ['hooks.auth:subscribe'],
      onBoot(ctx) {
        ctx.hooks.on('auth:registration:completed', (payload) => {
          seenEmail = payload.user.email // typed, no cast
        })
      },
    })

    const ctx = bootCtx()
    await wireRegisteredPlugins([p], ctx)

    await ctx.hooks.execute('auth:registration:completed', {
      user: { id: 'u1', email: 'new@user.com', role: 'user' },
    })
    expect(seenEmail).toBe('new@user.com')
  })

  it('gates services by capability: ctx.cap.email throws without email:send', async () => {
    let thrown: unknown
    const p = definePlugin({
      id: 'nogate',
      version: '1.0.0',
      capabilities: [], // did NOT declare email:send
      onBoot(ctx) {
        try {
          void ctx.cap.email
        } catch (e) {
          thrown = e
        }
      },
    })
    await wireRegisteredPlugins([p], bootCtx())
    expect(thrown).toBeInstanceOf(SonicCapabilityError)
  })

  it('resolves a declared capability through a host-supplied provider', async () => {
    const fakeEmail = { send: () => 'sent' }
    let resolved: unknown
    const p = definePlugin({
      id: 'sender',
      version: '1.0.0',
      capabilities: ['email:send'],
      onBoot(ctx) {
        resolved = ctx.cap.email
      },
    })
    // Host supplies providers on the boot context.
    await wireRegisteredPlugins([p], bootCtx({ providers: { email: () => fakeEmail } }))
    expect(resolved).toBe(fakeEmail)
  })

  it('exposes env on the enriched context', async () => {
    let seenEnv: unknown
    const p = definePlugin({
      id: 'envy',
      version: '1.0.0',
      onBoot(ctx) {
        seenEnv = ctx.env
      },
    })
    await wireRegisteredPlugins([p], bootCtx({ env: { DB: 'binding' } }))
    expect(seenEnv).toEqual({ DB: 'binding' })
  })
})

describe('definePlugin — declarative hooks', () => {
  it('flattens the typed hooks map into wirable hooks[] that fire on dispatch', async () => {
    let seenCollection = ''
    const p = definePlugin({
      id: 'declarative',
      version: '1.0.0',
      capabilities: ['hooks.content:subscribe'],
      hooks: {
        'content:after:create': (payload) => {
          // payload is narrowed to ContentEventPayload
          seenCollection = payload.collection
        },
      },
    })

    // Flattened onto hooks[] for the wire phase.
    expect(p.hooks).toHaveLength(1)
    expect(p.hooks?.[0]?.name).toBe('content:after:create')

    // Wire it and dispatch the canonical event → handler fires with the payload.
    const c: PluginBootContext = { hooks: new HookSystemImpl() }
    await wireRegisteredPlugins([p], c)
    await c.hooks.execute('content:after:create', { collection: 'posts', data: {} })
    expect(seenCollection).toBe('posts')
  })

  it('has no hooks[] when none are declared', () => {
    const p = definePlugin({ id: 'no-hooks', version: '1.0.0' })
    expect(p.hooks).toBeUndefined()
  })
})

describe('definePlugin — cron', () => {
  it('onCronTick receives the event and the enriched (typed) context', async () => {
    let firedFamily = ''
    let hasTypedHooks = false
    const p = definePlugin({
      id: 'reconciler',
      version: '1.0.0',
      capabilities: ['cron:register'],
      crons: [{ schedule: '*/15 * * * *', hookFamily: 'reconcile' }],
      onCronTick(event, ctx) {
        firedFamily = event.hookFamily
        hasTypedHooks = typeof ctx.hooks.on === 'function'
      },
    })

    const result = await dispatchCronTick([p], '*/15 * * * *', 1000, { hooks: new HookSystemImpl() })
    expect(firedFamily).toBe('reconcile')
    expect(hasTypedHooks).toBe(true)
    expect(result.invoked).toEqual([{ plugin: 'reconciler', hookFamily: 'reconcile' }])
  })
})
