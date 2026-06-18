/**
 * One-time password (OTP) login email. Sent by the OTP login plugin via the
 * caller-direct critical-path send (see design doc §10 — OTP is the
 * documented exception to the event-driven dispatch pattern because the
 * user is BLOCKED on the email's arrival to proceed; an in-process
 * dispatch with awaited result is required).
 *
 * Per scope memo §6.8 content discipline: code, expiry, "for your eyes
 * only" wording.
 *
 * Visual identity: SonicJS-dark baseline with prefers-color-scheme: light
 * fallback via the shared `_layout` helper.
 */
import { escapeHtml } from './_escape'
import { renderEmailLayout, renderCodeBlock, renderInfoLine } from './_layout'
import type { RenderedEmail } from './welcome'

export interface OtpEmailInput {
  user: { firstName?: string; email: string }
  code: string
  expiresAt: number
  siteName: string
}

export function renderOtpEmail(input: OtpEmailInput): RenderedEmail {
  const { user, code, expiresAt, siteName } = input
  const greeting = user.firstName ? `Hi ${user.firstName}` : 'Hi there'
  const subject = `Your ${siteName} login code: ${code}`
  const expiresIso = new Date(expiresAt).toISOString()

  const bodyHtml = `
    <p class="email-text" style="margin:0 0 12px 0;">${escapeHtml(greeting)},</p>
    <p class="email-text" style="margin:0 0 0 0;">Your one-time login code for ${escapeHtml(siteName)} is:</p>
    ${renderCodeBlock(code)}
    ${renderInfoLine('Expires at', `${expiresIso} (UTC)`)}
    <p class="email-text" style="margin:16px 0 12px 0;">Don't share this code with anyone — it's for your eyes only.</p>
    <p class="email-text" style="margin:0 0 12px 0;">If you didn't try to sign in, you can safely ignore this email.</p>
    <p class="email-muted" style="margin:16px 0 0 0;">— The ${escapeHtml(siteName)} team</p>
  `

  const html = renderEmailLayout({
    siteName,
    heading: 'Your login code',
    preheader: `Your ${siteName} login code: ${code} — expires ${expiresIso}`,
    bodyHtml,
  })

  const text = `${greeting},

Your one-time login code for ${siteName} is:

    ${code}

This code expires at ${expiresIso} (UTC). Don't share it with anyone — it's for your eyes only.

If you didn't try to sign in, you can safely ignore this email.

— The ${siteName} team
`

  return { subject, html, text }
}
