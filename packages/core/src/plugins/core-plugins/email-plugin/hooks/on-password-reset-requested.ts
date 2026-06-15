/**
 * `auth:password-reset:requested` hook handler — sends the password-reset
 * email. Closes #574 (which historically leaked the reset link through the
 * HTTP response body for dev convenience; PR-E moves it onto this event-
 * driven email path).
 *
 * The dispatcher passes `resetToken` only; this handler reconstructs the
 * `resetLink` from the configured site URL.
 */
import type { SonicHookHandler } from '../../../sdk/types'
import { getEmailService } from '../../../../services/email-service-singleton'
import { SiteConfigService } from '../services/site-config.service'
import { renderPasswordResetEmail } from '../templates/password-reset'

interface UserRow {
  id: string
  email: string
  first_name: string | null
}

export const onPasswordResetRequested: SonicHookHandler<'auth:password-reset:requested'> = async (
  ctx,
  event,
) => {
  const user = await ctx.env.DB
    .prepare('SELECT id, email, first_name FROM users WHERE id = ?')
    .bind(event.userId)
    .first<UserRow>()

  if (!user) {
    console.warn('[email-plugin] auth:password-reset:requested: user not found', {
      userId: event.userId,
    })
    return
  }

  const siteConfig = new SiteConfigService(ctx.env.DB, ctx.env)
  const { siteName, siteUrl } = await siteConfig.load()
  const resetLink = siteConfig.buildResetLink(siteUrl, event.resetToken)

  const { subject, html, text } = renderPasswordResetEmail({
    user: { firstName: user.first_name ?? undefined, email: user.email },
    resetLink,
    expiresAt: event.expiresAt,
    siteName,
  })

  const result = await getEmailService().send({
    to: user.email,
    subject,
    html,
    text,
    purpose: 'password_reset',
    userId: user.id,
    templateName: 'auth.password-reset',
    templateVariables: {
      firstName: user.first_name,
      siteName,
      expiresAt: event.expiresAt,
    },
  })

  if (result.status === 'failed_at_send') {
    console.warn('[email-plugin] auth:password-reset:requested: send failed', {
      event: event.type,
      purpose: 'password_reset',
      userId: event.userId,
      errorCode: result.errorCode,
      errorMessage: result.errorMessage,
    })
  }
}
