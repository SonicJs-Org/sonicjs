import { describe, it, expect } from 'vitest'
import { renderApiDocsPage } from '../components/api-docs-page'
import type { RouteMetadata } from '../../../../services'

const routes: RouteMetadata[] = [
  { method: 'GET', path: '/api/content', description: 'List content', authentication: false, category: 'Content', documented: true },
  { method: 'POST', path: '/api/content/:collection', description: 'Create', authentication: true, category: 'Content', documented: false },
]

describe('renderApiDocsPage', () => {
  it('renders both tabs and the endpoint catalog', () => {
    const html = renderApiDocsPage({ endpoints: routes, version: '3.0.0' })
    expect(html).toContain('API Reference')
    expect(html).toContain('tab-endpoints')
    expect(html).toContain('tab-interactive')
    expect(html).toContain('/api/content')
    // stats: 2 total, 1 public, 1 protected
    expect(html).toContain('Total Endpoints')
  })

  it('ESCAPES route-derived strings (N2 — no stored XSS)', () => {
    const evil: RouteMetadata[] = [
      { method: 'GET', path: '/api/<img src=x onerror=alert(1)>', description: '<script>alert(1)</script>', authentication: false, category: 'Content', documented: true },
    ]
    const html = renderApiDocsPage({ endpoints: evil })
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
    expect(html).not.toContain('<img src=x onerror=alert(1)>')
  })

  it('loads Scalar pinned + SRI (N1) and points it at the auth-gated spec', () => {
    const html = renderApiDocsPage({ endpoints: routes })
    expect(html).toContain('@scalar/api-reference@1.63.0')
    expect(html).toContain('sha384-bnRzGcRYqM9jbXxeIbNDWWD8mNMY0p8qvmfAyfcT5S7/I6E7bsyLprA0uIP2gUu7')
    expect(html).toContain('crossOrigin')
    expect(html).toContain('/admin/plugins/api-docs/openapi.json')
    // never the public core /api spec
    expect(html).not.toContain("data-url', '/api'")
  })

  it('renders inside the shared admin chrome', () => {
    const html = renderApiDocsPage({ endpoints: routes, user: { name: 'a@test', email: 'a@test', role: 'admin' } })
    expect(html).toContain('<!DOCTYPE html>')
    expect(html).toContain('SonicJS')
  })

  it('keeps data-description a well-formed attribute for undocumented routes', () => {
    // An empty description falls back to a styled <em> in the VISIBLE <p>, but the
    // data-description ATTRIBUTE (read by the search filter) must stay plain text —
    // the <em class="…"> quotes would otherwise break the double-quoted attribute.
    const undoc: RouteMetadata[] = [
      { method: 'GET', path: '/api/x', description: '', authentication: false, category: 'Content', documented: false },
    ]
    const html = renderApiDocsPage({ endpoints: undoc })
    // attribute is empty, not the <em> markup
    expect(html).toContain('data-description=""')
    expect(html).not.toContain('data-description="<em')
    // the styled fallback still appears in the visible paragraph
    expect(html).toContain('No description available')
  })
})
