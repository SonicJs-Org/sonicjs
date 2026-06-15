import { describe, it, expect } from 'vitest'
import { renderOtpEmail } from './otp'

describe('renderOtpEmail', () => {
  it('puts the code in subject + body and includes the for-your-eyes-only warning', () => {
    const out = renderOtpEmail({
      user: { firstName: 'Marco', email: 'marco@example.com' },
      code: '482915',
      expiresAt: Date.UTC(2026, 4, 13, 15, 5, 0),
      siteName: 'SonicJS',
    })

    expect(out.subject).toBe('Your SonicJS login code: 482915')
    expect(out.html).toContain('482915')
    expect(out.text).toContain('482915')
    expect(out.text).toMatch(/for your eyes only/i)
    expect(out.text).toContain('2026-05-13T15:05:00.000Z')
  })

  it('HTML-escapes the code (defense-in-depth against future codegen)', () => {
    const out = renderOtpEmail({
      user: { email: 'x@y.z' },
      code: '<script>',
      expiresAt: 0,
      siteName: 'SonicJS',
    })

    expect(out.html).not.toContain('<script>')
    expect(out.html).toContain('&lt;script&gt;')
  })

  it('HTML-escapes the siteName', () => {
    const out = renderOtpEmail({
      user: { email: 'x@y.z' },
      code: '482915',
      expiresAt: 0,
      siteName: '<b>SonicJS</b>',
    })

    expect(out.html).not.toContain('<b>SonicJS</b>')
    expect(out.html).toContain('&lt;b&gt;SonicJS&lt;/b&gt;')
  })

  it('applies the shared layout (color-scheme meta + hook classes)', () => {
    const out = renderOtpEmail({
      user: { email: 'x@y.z' },
      code: '482915',
      expiresAt: 0,
      siteName: 'SonicJS',
    })
    expect(out.html).toContain('color-scheme')
    expect(out.html).toContain('email-card')
    expect(out.html).toContain('email-code')
  })
})
