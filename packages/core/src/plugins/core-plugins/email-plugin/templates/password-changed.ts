/**
 * Password-changed confirmation email. Sent after
 * `auth:password-reset:completed` fires from `routes/auth.ts:~1347`.
 *
 * Per scope memo §6.8 content discipline: confirmation, timestamp,
 * "if not you, contact support" wording.
 *
 * Visual identity: SonicJS-dark baseline with prefers-color-scheme: light
 * fallback via the shared `_layout` helper.
 */
import { escapeHtml } from './_escape'
import { renderEmailLayout, renderTextLink, renderInfoLine } from './_layout'
import type { RenderedEmail } from './welcome'

export interface PasswordChangedEmailInput {
  user: { firstName?: string; email: string }
  siteName: string
  supportEmail: string
  when: number
}

export function renderPasswordChangedEmail(input: PasswordChangedEmailInput): RenderedEmail {
  const { user, siteName, supportEmail, when } = input
  const greeting = user.firstName ? `Hi ${user.firstName}` : 'Hi there'
  const subject = `Your ${siteName} password was changed`
  const whenIso = new Date(when).toISOString()

  const bodyHtml = `
    <p class="email-text" style="margin:0 0 12px 0;">${escapeHtml(greeting)},</p>
    <p class="email-text" style="margin:0 0 8px 0;">Your ${escapeHtml(siteName)} password was changed.</p>
    ${renderInfoLine('Changed at', `${whenIso} (UTC)`)}
    <p class="email-text" style="margin:16px 0 12px 0;">If this was you, no further action is needed.</p>
    <p class="email-text" style="margin:0 0 12px 0;">If you didn't change your password, contact support immediately at ${renderTextLink(`mailto:${supportEmail}`, supportEmail)} — your account may be compromised.</p>
    <p class="email-muted" style="margin:16px 0 0 0;">— The ${escapeHtml(siteName)} team</p>
  `

  const html = renderEmailLayout({
    siteName,
    heading: 'Password changed',
    preheader: `Your ${siteName} password was changed at ${whenIso}`,
    bodyHtml,
  })

  const text = `${greeting},

Your ${siteName} password was changed at ${whenIso} (UTC).

If this was you, no further action is needed.

If you didn't change your password, contact support immediately at ${supportEmail} — your account may be compromised.

— The ${siteName} team
`

  return { subject, html, text }
}
