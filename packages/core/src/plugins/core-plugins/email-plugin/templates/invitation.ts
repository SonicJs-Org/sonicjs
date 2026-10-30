/**
 * Invitation email template. Sent when an admin issues an invitation
 * via `POST /admin/users/invite`. The admin route renders + sends this
 * directly (no hook), since the admin UI needs the send-result to surface
 * in its response.
 *
 * The handler constructs `acceptLink` from the invitation token + site URL
 * config before calling this helper.
 *
 * Visual identity: SonicJS-dark baseline with prefers-color-scheme: light
 * fallback via the shared `_layout` helper (matches password-reset and
 * welcome).
 */
import { escapeHtml } from './_escape'
import { renderEmailLayout, renderPrimaryButton, renderTextLink, renderInfoLine } from './_layout'
import type { RenderedEmail } from './welcome'

export interface InvitationEmailInput {
  invitee: { firstName: string; lastName: string; email: string }
  inviter?: { firstName?: string | null; lastName?: string | null; email?: string | null }
  role: string
  acceptLink: string
  expiresAt: number
  siteName: string
}

function formatInviterName(inviter: InvitationEmailInput['inviter']): string | null {
  if (!inviter) return null
  const first = inviter.firstName?.trim()
  const last = inviter.lastName?.trim()
  if (first || last) return `${first ?? ''} ${last ?? ''}`.trim()
  return inviter.email?.trim() || null
}

export function renderInvitationEmail(input: InvitationEmailInput): RenderedEmail {
  const { invitee, inviter, role, acceptLink, expiresAt, siteName } = input
  const greeting = invitee.firstName ? `Hi ${invitee.firstName}` : 'Hi there'
  const subject = `You've been invited to ${siteName}`
  const expiresIso = new Date(expiresAt).toISOString()
  const inviterName = formatInviterName(inviter)
  const invitedByLine = inviterName
    ? `<p class="email-text" style="margin:0 0 12px 0;">${escapeHtml(inviterName)} has invited you to join <strong>${escapeHtml(siteName)}</strong> as ${escapeHtml(role)}.</p>`
    : `<p class="email-text" style="margin:0 0 12px 0;">You've been invited to join <strong>${escapeHtml(siteName)}</strong> as ${escapeHtml(role)}.</p>`

  const bodyHtml = `
    <p class="email-text" style="margin:0 0 12px 0;">${escapeHtml(greeting)},</p>
    ${invitedByLine}
    <p class="email-text" style="margin:0 0 0 0;">Click the button below to set your password and finish creating your account.</p>
    ${renderPrimaryButton(acceptLink, 'Accept invitation')}
    <p class="email-muted" style="margin:0 0 4px 0;font-size:13px;line-height:20px;">Or paste this URL into your browser:</p>
    <p class="email-text" style="margin:0 0 16px 0;font-size:13px;line-height:20px;word-break:break-all;">${renderTextLink(acceptLink)}</p>
    ${renderInfoLine('Expires at', `${expiresIso} (UTC)`)}
    <p class="email-text" style="margin:16px 0 12px 0;">If you weren't expecting this invitation, you can safely ignore this email — no account will be created.</p>
    <p class="email-muted" style="margin:16px 0 0 0;">— The ${escapeHtml(siteName)} team</p>
  `

  const html = renderEmailLayout({
    siteName,
    heading: `You're invited to ${siteName}`,
    preheader: `Accept your invitation to ${siteName} — link expires ${expiresIso}`,
    bodyHtml,
  })

  const inviterTextLine = inviterName
    ? `${inviterName} has invited you to join ${siteName} as ${role}.`
    : `You've been invited to join ${siteName} as ${role}.`

  const text = `${greeting},

${inviterTextLine}

Click the link below to set your password and finish creating your account:

${acceptLink}

This link expires at ${expiresIso} (UTC).

If you weren't expecting this invitation, you can safely ignore this email — no account will be created.

— The ${siteName} team
`

  return { subject, html, text }
}
