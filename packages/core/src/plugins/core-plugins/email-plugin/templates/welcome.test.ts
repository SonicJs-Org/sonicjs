import { describe, it, expect } from 'vitest'
import { renderWelcomeEmail } from './welcome'

describe('renderWelcomeEmail', () => {
  it('produces subject + html + text with siteName + loginUrl', () => {
    const out = renderWelcomeEmail({
      user: { firstName: 'Marco', email: 'marco@example.com' },
      siteName: 'SonicJS',
      loginUrl: 'https://example.com/login',
    })

    expect(out.subject).toBe('Welcome to SonicJS')
    expect(out.html).toContain('Hi Marco')
    expect(out.html).toContain('https://example.com/login')
    expect(out.text).toContain('Hi Marco')
    expect(out.text).toContain('https://example.com/login')
  })

  it('falls back to "Hi there" when firstName is omitted', () => {
    const out = renderWelcomeEmail({
      user: { email: 'anon@example.com' },
      siteName: 'SonicJS',
      loginUrl: 'https://example.com/login',
    })

    expect(out.html).toContain('Hi there')
    expect(out.text).toContain('Hi there')
  })

  it('HTML-escapes user-controlled fields to block injection', () => {
    const out = renderWelcomeEmail({
      user: { firstName: '<script>alert(1)</script>', email: 'x@y.z' },
      siteName: 'SonicJS',
      loginUrl: 'https://example.com/login',
    })

    expect(out.html).not.toContain('<script>alert(1)</script>')
    expect(out.html).toContain('&lt;script&gt;')
    // Plain-text body deliberately does NOT escape (text/plain is opaque to HTML).
    expect(out.text).toContain('<script>alert(1)</script>')
  })

  it('applies the shared layout (color-scheme meta + hook classes)', () => {
    const out = renderWelcomeEmail({
      user: { email: 'x@y.z' },
      siteName: 'SonicJS',
      loginUrl: 'https://example.com/login',
    })
    expect(out.html).toContain('color-scheme')
    expect(out.html).toContain('email-card')
    expect(out.html).toContain('email-button-a')
  })
})
