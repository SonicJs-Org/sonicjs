import { describe, it, expect, afterEach } from 'vitest'
import { HookSystemImpl } from '../../plugins/hook-system'
import { createTypedHooks } from '../../plugins/hooks/typed-hooks'
import {
  HOOK_EVENT_NAMES,
  isKnownHookEvent,
} from '../../plugins/hooks/catalog'
import {
  setHookSystem,
  getHookSystem,
  getTypedHooks,
  hasHookSystem,
  resetHookSystem,
} from '../../plugins/hooks/hook-system-singleton'

afterEach(() => {
  resetHookSystem()
})

describe('hook catalog', () => {
  it('lists every catalog event name and recognizes them', () => {
    expect(HOOK_EVENT_NAMES).toContain('auth:registration:completed')
    expect(HOOK_EVENT_NAMES).toContain('content:after:create')
    expect(isKnownHookEvent('auth:registration:completed')).toBe(true)
    expect(isKnownHookEvent('not:a:real:event')).toBe(false)
  })
})

describe('createTypedHooks', () => {
  it('runs a subscribed handler with the typed payload on dispatch', async () => {
    const hooks = createTypedHooks(new HookSystemImpl())
    let seenEmail = ''

    hooks.on('auth:registration:completed', (payload) => {
      // payload is narrowed — no cast needed
      seenEmail = payload.user.email
    })

    await hooks.dispatch('auth:registration:completed', {
      user: { id: 'u1', email: 'a@b.com', role: 'user' },
    })

    expect(seenEmail).toBe('a@b.com')
  })

  it('threads a mutated payload through the chain and returns it', async () => {
    const hooks = createTypedHooks(new HookSystemImpl())

    hooks.on('content:after:create', (payload) => {
      payload.data.added = true
      return payload
    })

    const out = await hooks.dispatch('content:after:create', { collection: 'posts', data: { title: 'x' } })
    expect(out.data).toEqual({ title: 'x', added: true })
  })

  it('preserves the payload when a handler returns void', async () => {
    const hooks = createTypedHooks(new HookSystemImpl())
    hooks.on('content:after:update', () => {
      /* returns void — payload should be preserved */
    })

    const payload = { collection: 'posts', id: '1', data: { title: 'keep' } }
    const out = await hooks.dispatch('content:after:update', payload)
    expect(out.data).toEqual({ title: 'keep' })
  })

  it('runs handlers in priority order (lower first)', async () => {
    const hooks = createTypedHooks(new HookSystemImpl())
    const order: string[] = []
    hooks.on('content:after:update', () => void order.push('late'), 100)
    hooks.on('content:after:update', () => void order.push('early'), 1)

    await hooks.dispatch('content:after:update', { collection: 'posts', data: {} })
    expect(order).toEqual(['early', 'late'])
  })

  it('returns the original payload when no handler is subscribed', async () => {
    const hooks = createTypedHooks(new HookSystemImpl())
    const payload = { collection: 'posts', data: { a: 1 } }
    const out = await hooks.dispatch('content:after:delete', payload)
    expect(out).toEqual(payload)
  })

  it('a `content:before:*` handler can mutate the payload before the write', async () => {
    const hooks = createTypedHooks(new HookSystemImpl())
    hooks.on('content:before:create', (payload) => {
      payload.data.slug = 'generated'
      return payload
    })
    const out = await hooks.dispatch('content:before:create', { collection: 'posts', data: {} })
    expect(out.data.slug).toBe('generated')
  })
})

describe('legacy event aliases (deprecation window)', () => {
  it('a legacy subscription fires on the canonical dispatch, warning once', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const hooks = createTypedHooks(new HookSystemImpl())
    let fired = 0

    // Legacy name still compiles + subscribes; resolves to content:after:create.
    hooks.on('content:create', () => {
      fired++
    })

    await hooks.dispatch('content:after:create', { collection: 'posts', data: {} })
    expect(fired).toBe(1)
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('"content:create" is deprecated'))
  })
})

// ── Type-level assertions ────────────────────────────────────────────────────
// Never executed; validated by `tsc --noEmit`. Proves the catalog narrows the
// payload at the subscribe site and rejects unknown events/fields.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function __typeChecks(): void {
  const hooks = createTypedHooks(new HookSystemImpl())

  hooks.on('auth:registration:completed', (payload) => {
    const email: string = payload.user.email // ✓ narrowed
    void email
    // @ts-expect-error — 'nope' is not a field on the registration payload
    void payload.user.nope
  })

  hooks.on('content:after:create', (payload) => {
    const collection: string = payload.collection // ✓ narrowed
    void collection
    // Canonical actor shape: content events use `user.id` (NOT `userId`).
    const actorId: string | undefined = payload.user?.id
    void actorId
    // @ts-expect-error — `userId` was removed; the canonical actor field is `id`
    void payload.user?.userId
  })

  // Legacy alias still compiles and is typed to the canonical payload.
  hooks.on('content:create', (payload) => {
    const collection: string = payload.collection
    void collection
  })

  // Same actor shape across event families (content `user` and auth `user` agree).
  hooks.on('auth:registration:completed', (p) => {
    const id: string = p.user.id
    void id
  })

  // @ts-expect-error — 'not:a:real:event' is not in the catalog
  hooks.on('not:a:real:event', () => {})

  // @ts-expect-error — payload shape must match the event
  void hooks.dispatch('auth:registration:completed', { wrong: true })
}

describe('hook-system singleton', () => {
  it('throws when read before being set', () => {
    expect(hasHookSystem()).toBe(false)
    expect(() => getHookSystem()).toThrow(/not been initialized/)
  })

  it('returns the set hook system and reports presence', () => {
    const hs = new HookSystemImpl()
    setHookSystem(hs)
    expect(hasHookSystem()).toBe(true)
    expect(getHookSystem()).toBe(hs)
  })

  it('is idempotent — last write wins, no throw on re-set', () => {
    const a = new HookSystemImpl()
    const b = new HookSystemImpl()
    setHookSystem(a)
    expect(() => setHookSystem(b)).not.toThrow()
    expect(getHookSystem()).toBe(b)
  })

  it('getTypedHooks() dispatches through the singleton', async () => {
    setHookSystem(new HookSystemImpl())
    let ran = false
    getTypedHooks().on('auth:password-reset:completed', () => {
      ran = true
    })
    await getTypedHooks().dispatch('auth:password-reset:completed', {
      user: { id: 'u1', email: 'a@b.com' },
    })
    expect(ran).toBe(true)
  })

  it('resetHookSystem() clears it', () => {
    setHookSystem(new HookSystemImpl())
    resetHookSystem()
    expect(hasHookSystem()).toBe(false)
  })
})
