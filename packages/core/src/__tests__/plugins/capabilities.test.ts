import { describe, it, expect } from 'vitest'
import {
  FIXED_CAPABILITIES,
  isKnownCapability,
  SonicCapabilityError,
  hasCapability,
  assertCapability,
  validateCapabilities,
  createCapabilityContext,
} from '../../plugins/capabilities'
import { createServiceSingleton } from '../../plugins/singletons/service-singleton'

describe('capability vocabulary', () => {
  it('recognizes fixed capabilities', () => {
    expect(isKnownCapability('email:send')).toBe(true)
    expect(FIXED_CAPABILITIES).toContain('cron:register')
  })

  it('recognizes valid db:<table> capabilities', () => {
    expect(isKnownCapability('db:email_log')).toBe(true)
    expect(isKnownCapability('db:_private')).toBe(true)
  })

  it('rejects unknown or malformed capabilities', () => {
    expect(isKnownCapability('totally:made-up')).toBe(false)
    expect(isKnownCapability('db:')).toBe(false)
    expect(isKnownCapability('db:has-dash')).toBe(false)
    expect(isKnownCapability('db:1starts-with-number')).toBe(false)
  })

  it('validateCapabilities returns only the unknown entries', () => {
    expect(validateCapabilities(['email:send', 'db:logs'])).toEqual([])
    expect(validateCapabilities(['email:send', 'nope', 'also:bad'])).toEqual(['nope', 'also:bad'])
  })
})

describe('hasCapability / assertCapability', () => {
  it('hasCapability checks membership', () => {
    expect(hasCapability(['email:send'], 'email:send')).toBe(true)
    expect(hasCapability(['email:send'], 'cache:read')).toBe(false)
  })

  it('assertCapability throws SonicCapabilityError for a missing capability', () => {
    expect(() => assertCapability(['cache:read'], 'email:send', 'my-plugin')).toThrow(SonicCapabilityError)
    try {
      assertCapability([], 'email:send', 'my-plugin')
    } catch (e) {
      expect(e).toBeInstanceOf(SonicCapabilityError)
      expect((e as SonicCapabilityError).capability).toBe('email:send')
      expect((e as SonicCapabilityError).plugin).toBe('my-plugin')
    }
  })

  it('assertCapability is a no-op when granted', () => {
    expect(() => assertCapability(['email:send'], 'email:send')).not.toThrow()
  })
})

describe('createCapabilityContext', () => {
  const emailProvider = () => ({ send: () => 'sent' })

  it('returns the provider when the capability is granted', () => {
    const ctx = createCapabilityContext(['email:send'], { email: emailProvider }, 'mailer')
    expect((ctx.email as any).send()).toBe('sent')
  })

  it('throws SonicCapabilityError when the capability is NOT granted', () => {
    const ctx = createCapabilityContext([], { email: emailProvider }, 'mailer')
    expect(() => ctx.email).toThrow(SonicCapabilityError)
    expect(() => ctx.email).toThrow(/email:send/)
  })

  it('cache accessor accepts either cache:read or cache:write', () => {
    const cacheProvider = () => ({ name: 'cache' })
    const readOnly = createCapabilityContext(['cache:read'], { cache: cacheProvider })
    const writeOnly = createCapabilityContext(['cache:write'], { cache: cacheProvider })
    expect((readOnly.cache as any).name).toBe('cache')
    expect((writeOnly.cache as any).name).toBe('cache')
    const none = createCapabilityContext([], { cache: cacheProvider })
    expect(() => none.cache).toThrow(SonicCapabilityError)
  })

  it('throws a clear (non-capability) error if granted but no provider supplied', () => {
    const ctx = createCapabilityContext(['email:send'], {}, 'mailer')
    expect(() => ctx.email).toThrow(/no provider was supplied/)
  })

  it('has() and require() reflect the grant set', () => {
    const ctx = createCapabilityContext(['email:send', 'db:logs'])
    expect(ctx.has('email:send')).toBe(true)
    expect(ctx.has('cache:read')).toBe(false)
    expect(ctx.capabilities).toEqual(['email:send', 'db:logs'])
    expect(() => ctx.require('email:send')).not.toThrow()
    expect(() => ctx.require('cache:read')).toThrow(SonicCapabilityError)
  })

  it('does not call a provider until the accessor is read (lazy)', () => {
    let calls = 0
    const ctx = createCapabilityContext(['email:send'], {
      email: () => {
        calls++
        return {}
      },
    })
    expect(calls).toBe(0)
    void ctx.email
    void ctx.email
    expect(calls).toBe(2) // called per access (host can memoize in the provider if desired)
  })
})

describe('createServiceSingleton', () => {
  interface Svc {
    name: string
  }

  it('throws before being set', () => {
    const s = createServiceSingleton<Svc>('EmailService')
    expect(s.has()).toBe(false)
    expect(() => s.get()).toThrow(/EmailService has not been initialized/)
  })

  it('returns the set instance', () => {
    const s = createServiceSingleton<Svc>('EmailService')
    const svc = { name: 'email' }
    s.set(svc)
    expect(s.has()).toBe(true)
    expect(s.get()).toBe(svc)
  })

  it('is idempotent — last write wins', () => {
    const s = createServiceSingleton<Svc>('X')
    s.set({ name: 'a' })
    expect(() => s.set({ name: 'b' })).not.toThrow()
    expect(s.get().name).toBe('b')
  })

  it('is reachable without any request env (cron-safe)', () => {
    // The whole point: a handler with no `c.env` can still read the service.
    const s = createServiceSingleton<Svc>('CronReachable')
    s.set({ name: 'reachable' })
    const fromCronLikeContext = () => s.get()
    expect(fromCronLikeContext().name).toBe('reachable')
  })

  it('reset() clears the slot', () => {
    const s = createServiceSingleton<Svc>('X')
    s.set({ name: 'a' })
    s.reset()
    expect(s.has()).toBe(false)
  })

  it('keeps separate slots independent', () => {
    const a = createServiceSingleton<Svc>('A')
    const b = createServiceSingleton<Svc>('B')
    a.set({ name: 'a' })
    expect(b.has()).toBe(false)
  })
})
