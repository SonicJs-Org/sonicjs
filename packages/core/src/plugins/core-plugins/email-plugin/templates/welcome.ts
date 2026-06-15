/**
 * Welcome email template. Sent after a successful registration (API or
 * form path) via the `auth:registration:completed` hook handler.
 *
 * Per scope memo §6.8 content discipline: brief greeting, link to login,
 * mention of help/support, no marketing copy.
 *
 * Visual identity: SonicJS-dark baseline with prefers-color-scheme: light
 * fallback via the shared `_layout` helper.
 */
import { escapeHtml } from './_escape'
import { renderEmailLayout, renderPrimaryButton, renderTextLink } from './_layout'

export interface WelcomeEmailInput {
  user: { firstName?: string; email: string }
  siteName: string
  loginUrl: string
}

export interface RenderedEmail {
  subject: string
  html: string
  text: string
}

export function renderWelcomeEmail(input: WelcomeEmailInput): RenderedEmail {
  const { user, siteName, loginUrl } = input
  const greeting = user.firstName ? `Hi ${user.firstName}` : 'Hi there'
  const subject = `Welcome to ${siteName}`

  const bodyHtml = `
    <p class="email-text" style="margin:0 0 12px 0;">${escapeHtml(greeting)},</p>
    <p class="email-text" style="margin:0 0 8px 0;">Your ${escapeHtml(siteName)} account is ready. You can sign in any time below.</p>
    ${renderPrimaryButton(loginUrl, 'Sign in')}
    <p class="email-muted" style="margin:0 0 4px 0;font-size:13px;line-height:20px;">Or paste this URL into your browser:</p>
    <p class="email-text" style="margin:0 0 16px 0;font-size:13px;line-height:20px;word-break:break-all;">${renderTextLink(loginUrl)}</p>
    <p class="email-text" style="margin:0 0 12px 0;">If you have any questions or need help, just reply to this email.</p>
    <p class="email-muted" style="margin:16px 0 0 0;">— The ${escapeHtml(siteName)} team</p>
  `

  const html = renderEmailLayout({
    siteName,
    heading: `Welcome to ${siteName}`,
    preheader: `Your ${siteName} account is ready. Sign in any time.`,
    bodyHtml,
  })

  const text = `${greeting},

Your ${siteName} account is ready. You can sign in any time at ${loginUrl}.

If you have any questions or need help, just reply to this email.

— The ${siteName} team
`

  return { subject, html, text }
}
