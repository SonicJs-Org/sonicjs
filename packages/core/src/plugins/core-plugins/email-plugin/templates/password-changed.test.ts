import { describe, it, expect } from 'vitest'
import { renderPasswordChangedEmail } from './password-changed'

describe('renderPasswordChangedEmail', () => {
  it('includes timestamp + support contact + warning copy', () => {
    const out = renderPasswordChangedEmail({
      user: { firstName: 'Marco', email: 'marco@example.com' },
      siteName: 'SonicJS',
      supportEmail: 'support@sonicjs.example',
      when: Date.UTC(2026, 4, 13, 18, 30, 0),
    })

    expect(out.subject).toBe('Your SonicJS password was changed')
    expect(out.html).toContain('2026-05-13T18:30:00.000Z')
    expect(out.html).toContain('mailto:support@sonicjs.example')
    expect(out.html).toMatch(/contact support immediately/i)

    expect(out.text).toContain('2026-05-13T18:30:00.000Z')
    expect(out.text).toContain('support@sonicjs.example')
    expect(out.text).toMatch(/contact support immediately/i)
  })

  it('falls back to "Hi there" when firstName is omitted', () => {
    const out = renderPasswordChangedEmail({
      user: { email: 'anon@example.com' },
      siteName: 'SonicJS',
      supportEmail: 'support@example.com',
      when: 0,
    })

    expect(out.html).toContain('Hi there')
    expect(out.text).toContain('Hi there')
  })

  it('applies the shared layout (color-scheme meta + hook classes)', () => {
    const out = renderPasswordChangedEmail({
      user: { email: 'x@y.z' },
      siteName: 'SonicJS',
      supportEmail: 'support@example.com',
      when: 0,
    })
    expect(out.html).toContain('color-scheme')
    expect(out.html).toContain('email-card')
    expect(out.html).toContain('email-link')
  })
})
