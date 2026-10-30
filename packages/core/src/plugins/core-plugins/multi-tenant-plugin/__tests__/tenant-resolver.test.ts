// Pure-logic coverage for the tenant resolution precedence (resolveTenantSlug). No DB needed —
// the resolver takes a snapshot of registry state + the request's header/cookie/host.
import { describe, it, expect } from 'vitest'
import { resolveTenantSlug } from '../../../../middleware/tenant'

function state(overrides: any = {}) {
  return {
    pluginActive: true,
    settings: { headerName: 'X-Tenant-Id', subdomainResolution: false, rootDomain: '' },
    tenants: new Map([
      ['default', { name: 'Default', status: 'active' }],
      ['acme', { name: 'Acme', status: 'active' }],
      ['beta', { name: 'Beta', status: 'active' }],
      ['frozen', { name: 'Frozen', status: 'inactive' }],
    ]),
    domains: new Map([['acme.example.com', 'acme']]),
    ...overrides,
  }
}

const req = (o: any = {}) => ({ header: undefined, cookie: undefined, host: undefined, ...o })

describe('resolveTenantSlug', () => {
  it('returns default when the plugin is inactive, ignoring all signals', () => {
    const s = state({ pluginActive: false })
    expect(resolveTenantSlug(s, req({ header: 'acme', cookie: 'beta', host: 'acme.example.com' }))).toBe('default')
  })

  it('header wins over cookie and host', () => {
    expect(resolveTenantSlug(state(), req({ header: 'acme', cookie: 'beta', host: 'beta.example.com' }))).toBe('acme')
  })

  it('cookie wins over host when no header', () => {
    expect(resolveTenantSlug(state(), req({ cookie: 'beta', host: 'acme.example.com' }))).toBe('beta')
  })

  it('exact domain mapping resolves when no header/cookie', () => {
    expect(resolveTenantSlug(state(), req({ host: 'acme.example.com' }))).toBe('acme')
  })

  it('host with port is normalized before domain match', () => {
    expect(resolveTenantSlug(state(), req({ host: 'acme.example.com:8787' }))).toBe('acme')
  })

  it('unknown header falls through to default (no leak)', () => {
    expect(resolveTenantSlug(state(), req({ header: 'ghost' }))).toBe('default')
  })

  it('inactive tenant is never resolved', () => {
    expect(resolveTenantSlug(state(), req({ header: 'frozen' }))).toBe('default')
    expect(resolveTenantSlug(state(), req({ cookie: 'frozen' }))).toBe('default')
  })

  it('subdomain resolution only applies when enabled and root domain is set', () => {
    const off = state()
    expect(resolveTenantSlug(off, req({ host: 'beta.example.com' }))).toBe('default')

    const on = state({ settings: { headerName: 'X-Tenant-Id', subdomainResolution: true, rootDomain: 'example.com' } })
    expect(resolveTenantSlug(on, req({ host: 'beta.example.com' }))).toBe('beta')
    // nested subdomain is not a single-label tenant → no match
    expect(resolveTenantSlug(on, req({ host: 'a.beta.example.com' }))).toBe('default')
    // unknown subdomain → default
    expect(resolveTenantSlug(on, req({ host: 'ghost.example.com' }))).toBe('default')
  })

  it('case-insensitive header/cookie matching', () => {
    expect(resolveTenantSlug(state(), req({ header: 'ACME' }))).toBe('acme')
    expect(resolveTenantSlug(state(), req({ cookie: 'Beta' }))).toBe('beta')
  })
})

describe('resolveTenantSlug — membership gate', () => {
  const enforce = (slugs: string[]) => ({ enforceMembership: true, memberSlugs: new Set(slugs) })

  it('accepts a header tenant the user is a member of', () => {
    expect(resolveTenantSlug(state(), req({ header: 'acme' }), enforce(['acme']))).toBe('acme')
  })

  it('rejects a header tenant the user is NOT a member of → default (no cross-tenant leak)', () => {
    expect(resolveTenantSlug(state(), req({ header: 'acme' }), enforce([]))).toBe('default')
  })

  it('rejects a cookie tenant the user is NOT a member of → default', () => {
    expect(resolveTenantSlug(state(), req({ cookie: 'acme' }), enforce(['beta']))).toBe('default')
  })

  it("'default' is always allowed even with no memberships", () => {
    expect(resolveTenantSlug(state(), req({ cookie: 'default' }), enforce([]))).toBe('default')
  })

  it('gates domain resolution too when enforcing (authed non-member on a tenant domain)', () => {
    expect(resolveTenantSlug(state(), req({ host: 'acme.example.com' }), enforce([]))).toBe('default')
    expect(resolveTenantSlug(state(), req({ host: 'acme.example.com' }), enforce(['acme']))).toBe('acme')
  })

  it('gates subdomain resolution when enforcing', () => {
    const on = state({ settings: { headerName: 'X-Tenant-Id', subdomainResolution: true, rootDomain: 'example.com' } })
    expect(resolveTenantSlug(on, req({ host: 'beta.example.com' }), enforce([]))).toBe('default')
    expect(resolveTenantSlug(on, req({ host: 'beta.example.com' }), enforce(['beta']))).toBe('beta')
  })

  it('anonymous requests (enforce off) are ungated — public routing unaffected', () => {
    expect(resolveTenantSlug(state(), req({ header: 'acme' }), { enforceMembership: false })).toBe('acme')
    expect(resolveTenantSlug(state(), req({ host: 'acme.example.com' }), { enforceMembership: false })).toBe('acme')
  })

  it('falls through past a non-member header to a member cookie', () => {
    expect(resolveTenantSlug(state(), req({ header: 'acme', cookie: 'beta' }), enforce(['beta']))).toBe('beta')
  })
})
