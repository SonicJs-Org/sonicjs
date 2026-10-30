/**
 * Password reset email template. Sent after `auth:password-reset:requested`
 * fires from `routes/auth.ts` (closes issue #574 — the dev-mode reset link
 * leaked through the response body until PR-E moved it onto the
 * event-driven email path).
 *
 * Per scope memo §6.8 content discipline: the reset link, expiry, "if not
 * you, ignore" wording.
 *
 * The handler constructs `resetLink` from `event.resetToken` + site URL
 * config before calling this helper (the event payload carries only the
 * raw `resetToken`, never the assembled URL).
 *
 * Visual identity: SonicJS-dark baseline with prefers-color-scheme: light
 * fallback via the shared `_layout` helper.
 */
import { escapeHtml } from './_escape'
import { renderEmailLayout, renderPrimaryButton, renderTextLink, renderInfoLine } from './_layout'
import type { RenderedEmail } from './welcome'

export interface PasswordResetEmailInput {
  user: { firstName?: string; email: string }
  resetLink: string
  expiresAt: number
  siteName: string
}

export function renderPasswordResetEmail(input: PasswordResetEmailInput): RenderedEmail {
  const { user, resetLink, expiresAt, siteName } = input
  const greeting = user.firstName ? `Hi ${user.firstName}` : 'Hi there'
  const subject = `Reset your ${siteName} password`
  const expiresIso = new Date(expiresAt).toISOString()

  const bodyHtml = `
    <p class="email-text" style="margin:0 0 12px 0;">${escapeHtml(greeting)},</p>
    <p class="email-text" style="margin:0 0 0 0;">We received a request to reset the password for your ${escapeHtml(siteName)} account. Click the button below to choose a new password.</p>
    ${renderPrimaryButton(resetLink, 'Choose a new password')}
    <p class="email-muted" style="margin:0 0 4px 0;font-size:13px;line-height:20px;">Or paste this URL into your browser:</p>
    <p class="email-text" style="margin:0 0 16px 0;font-size:13px;line-height:20px;word-break:break-all;">${renderTextLink(resetLink)}</p>
    ${renderInfoLine('Expires at', `${expiresIso} (UTC)`)}
    <p class="email-text" style="margin:16px 0 12px 0;">If you didn't request a password reset, you can safely ignore this email — your password won't be changed.</p>
    <p class="email-muted" style="margin:16px 0 0 0;">— The ${escapeHtml(siteName)} team</p>
  `

  const html = renderEmailLayout({
    siteName,
    heading: 'Reset your password',
    preheader: `Reset your ${siteName} password — link expires ${expiresIso}`,
    bodyHtml,
  })

  const text = `${greeting},

We received a request to reset the password for your ${siteName} account. Open the link below to choose a new password:

${resetLink}

This link expires at ${expiresIso} (UTC).

If you didn't request a password reset, you can safely ignore this email — your password won't be changed.

— The ${siteName} team
`

  return { subject, html, text }
}
