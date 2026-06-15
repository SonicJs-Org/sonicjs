import { describe, it, expect } from 'vitest'
import { SiteConfigService } from './site-config.service'

// SiteConfigService.buildVerificationUrl is a pure formatter — no DB calls.
// The test exercises the trailing-slash strip + URL-encoding contract that
// the email-plugin templates rely on (mirrors buildResetLink / buildMagicLinkUrl).
describe('SiteConfigService.buildVerificationUrl', () => {
  const svc = new SiteConfigService({} as D1Database)

  it('strips a single trailing slash from siteUrl', () => {
    expect(svc.buildVerificationUrl('https://example.com/', 'abc')).toBe(
      'https://example.com/auth/verify-email?token=abc',
    )
  })

  it('leaves a non-trailing-slash siteUrl unchanged', () => {
    expect(svc.buildVerificationUrl('https://example.com', 'abc')).toBe(
      'https://example.com/auth/verify-email?token=abc',
    )
  })

  it('URL-encodes the token (defense against tokens with special chars)', () => {
    // crypto.randomUUID() is safe, but the contract should not break if a
    // future implementation switches to a token format with reserved chars.
    expect(svc.buildVerificationUrl('https://example.com', 'a/b+c=d')).toBe(
      'https://example.com/auth/verify-email?token=a%2Fb%2Bc%3Dd',
    )
  })
})
