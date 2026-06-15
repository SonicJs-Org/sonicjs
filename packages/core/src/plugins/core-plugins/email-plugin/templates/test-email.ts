/**
 * Test email template. Sent by the email-plugin's admin `/admin/email/test`
 * endpoint to confirm the CF Email Service binding is working end-to-end.
 *
 * Per scope memo §6.8 content discipline: literal "this is a test
 * confirming binding works" wording. No marketing, no help links — just
 * the verification confirmation.
 *
 * Visual identity: SonicJS-dark baseline with prefers-color-scheme: light
 * fallback via the shared `_layout` helper.
 */
import { escapeHtml } from './_escape'
import { renderEmailLayout } from './_layout'
import type { RenderedEmail } from './welcome'

export interface TestEmailInput {
  siteName: string
}

export function renderTestEmail(input: TestEmailInput): RenderedEmail {
  const { siteName } = input
  const subject = `${siteName} email test`

  const bodyHtml = `
    <p class="email-text" style="margin:0 0 12px 0;">This is a test email from ${escapeHtml(siteName)} confirming the Cloudflare Email Service binding is working end-to-end.</p>
    <p class="email-text" style="margin:0 0 12px 0;">If you received this, the send path, the email log, and the from-address configuration are all set up correctly.</p>
    <p class="email-muted" style="margin:16px 0 0 0;">— Sent by ${escapeHtml(siteName)}'s email-plugin admin test endpoint</p>
  `

  const html = renderEmailLayout({
    siteName,
    heading: 'Email service test',
    preheader: `${siteName} email service binding test`,
    bodyHtml,
  })

  const text = `This is a test email from ${siteName} confirming the Cloudflare Email Service binding is working end-to-end.

If you received this, the send path, the email log, and the from-address configuration are all set up correctly.

— Sent by ${siteName}'s email-plugin admin test endpoint
`

  return { subject, html, text }
}
