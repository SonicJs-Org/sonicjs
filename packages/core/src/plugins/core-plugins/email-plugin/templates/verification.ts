/**
 * Email verification email template. Sent after a user registers (when
 * `general.verificationRequired` is on) and from the resend endpoint.
 *
 * Caller-direct send (registration / resend handler), mirroring the
 * critical-path semantics of OTP and magic-link — the user is blocked
 * on the email's arrival to proceed (they can't access /admin until
 * they click the link).
 *
 * Per scope memo §6.8 content discipline: a single verify link, a 24h
 * expiry note, and "if not you, ignore" wording. No marketing copy.
 *
 * Visual identity: SonicJS-dark baseline with prefers-color-scheme:
 * light fallback via the shared `_layout` helper.
 */
import { escapeHtml } from './_escape'
import { renderEmailLayout, renderPrimaryButton, renderTextLink } from './_layout'
import type { RenderedEmail } from './welcome'

export interface VerificationEmailInput {
  user: { firstName?: string; email: string }
  verifyUrl: string
  siteName: string
}

export function renderVerificationEmail(input: VerificationEmailInput): RenderedEmail {
  const { user, verifyUrl, siteName } = input
  const greeting = user.firstName ? `Hi ${user.firstName}` : 'Hi there'
  const subject = `Verify your email address for ${siteName}`

  const bodyHtml = `
    <p class="email-text" style="margin:0 0 12px 0;">${escapeHtml(greeting)},</p>
    <p class="email-text" style="margin:0 0 0 0;">Welcome to ${escapeHtml(siteName)} — please confirm your email address by clicking the button below.</p>
    ${renderPrimaryButton(verifyUrl, 'Verify Email Address')}
    <p class="email-muted" style="margin:0 0 4px 0;font-size:13px;line-height:20px;">Or paste this URL into your browser:</p>
    <p class="email-text" style="margin:0 0 16px 0;font-size:13px;line-height:20px;word-break:break-all;">${renderTextLink(verifyUrl)}</p>
    <p class="email-text" style="margin:16px 0 12px 0;">This link expires in 24 hours.</p>
    <p class="email-text" style="margin:0 0 12px 0;">If you didn't create an account, you can safely ignore this email.</p>
    <p class="email-muted" style="margin:16px 0 0 0;">— The ${escapeHtml(siteName)} team</p>
  `

  const html = renderEmailLayout({
    siteName,
    heading: 'Verify your email',
    preheader: `Verify your ${siteName} email address — link expires in 24 hours`,
    bodyHtml,
  })

  const text = `${greeting},

Welcome to ${siteName} — please confirm your email address by opening the link below:

${verifyUrl}

This link expires in 24 hours.

If you didn't create an account, you can safely ignore this email.

— The ${siteName} team
`

  return { subject, html, text }
}
