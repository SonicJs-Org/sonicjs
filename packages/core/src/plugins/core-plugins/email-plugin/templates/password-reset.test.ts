import { describe, it, expect } from 'vitest'
import { renderPasswordResetEmail } from './password-reset'

describe('renderPasswordResetEmail', () => {
  const baseInput = {
    user: { firstName: 'Marco', email: 'marco@example.com' },
    resetLink: 'https://example.com/auth/reset?token=abc123',
    expiresAt: Date.UTC(2026, 4, 13, 15, 0, 0),
    siteName: 'SonicJS',
  }

  it('includes reset link, expiry, and ignore-instructions in both bodies', () => {
    const out = renderPasswordResetEmail(baseInput)

    expect(out.subject).toBe('Reset your SonicJS password')
    expect(out.html).toContain('https://example.com/auth/reset?token=abc123')
    expect(out.html).toContain('2026-05-13T15:00:00.000Z')
    expect(out.html).toMatch(/safely ignore/i)

    expect(out.text).toContain('https://example.com/auth/reset?token=abc123')
    expect(out.text).toContain('2026-05-13T15:00:00.000Z')
    expect(out.text).toMatch(/safely ignore/i)
  })

  it('uses generic greeting when firstName is absent', () => {
    const out = renderPasswordResetEmail({
      ...baseInput,
      user: { firstName: undefined as unknown as string, email: 'anon@example.com' },
    })
    expect(out.html).toContain('Hi there')
    expect(out.text).toContain('Hi there')
  })

  it('HTML-escapes user-controlled fields', () => {
    const out = renderPasswordResetEmail({
      ...baseInput,
      user: { firstName: '"><img src=x onerror=alert(1)>', email: 'x@y.z' },
    })

    expect(out.html).not.toContain('<img src=x onerror=alert(1)>')
    expect(out.html).toContain('&quot;&gt;')
  })

  it('applies the shared layout (color-scheme meta + hook classes)', () => {
    const out = renderPasswordResetEmail(baseInput)
    expect(out.html).toContain('color-scheme')
    expect(out.html).toContain('email-card')
    expect(out.html).toContain('email-button-a')
  })
})
