import { describe, it, expect } from 'vitest'
import { renderTestEmail } from './test-email'

describe('renderTestEmail', () => {
  it('produces a confirmation-style subject + body identifying the site', () => {
    const out = renderTestEmail({ siteName: 'SonicJS' })

    expect(out.subject).toBe('SonicJS email test')
    expect(out.html).toContain('SonicJS')
    expect(out.html).toMatch(/test email/i)
    expect(out.text).toContain('SonicJS')
    expect(out.text).toMatch(/test email/i)
  })

  it('HTML-escapes the siteName', () => {
    const out = renderTestEmail({ siteName: '<b>SonicJS</b>' })

    expect(out.html).not.toContain('<b>SonicJS</b>')
    expect(out.html).toContain('&lt;b&gt;SonicJS&lt;/b&gt;')
  })

  it('applies the shared layout (color-scheme meta + hook classes)', () => {
    const out = renderTestEmail({ siteName: 'SonicJS' })
    expect(out.html).toContain('color-scheme')
    expect(out.html).toContain('email-card')
    expect(out.html).toContain('email-heading')
  })
})
