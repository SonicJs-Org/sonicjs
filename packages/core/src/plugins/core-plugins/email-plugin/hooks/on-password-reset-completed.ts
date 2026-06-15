/**
 * `auth:password-reset:completed` hook handler — sends the
 * password-changed confirmation email.
 *
 * The dispatcher fires AFTER the user's password has been updated; this
 * handler is informational ("your password just changed; if it wasn't you,
 * contact support").
 */
import type { SonicHookHandler } from '../../../sdk/types'
import { getEmailService } from '../../../../services/email-service-singleton'
import { SiteConfigService } from '../services/site-config.service'
import { renderPasswordChangedEmail } from '../templates/password-changed'

interface UserRow {
  id: string
  email: string
  first_name: string | null
}

export const onPasswordResetCompleted: SonicHookHandler<'auth:password-reset:completed'> = async (
  ctx,
  event,
) => {
  const user = await ctx.env.DB
    .prepare('SELECT id, email, first_name FROM users WHERE id = ?')
    .bind(event.userId)
    .first<UserRow>()

  if (!user) {
    console.warn('[email-plugin] auth:password-reset:completed: user not found', {
      userId: event.userId,
    })
    return
  }

  const siteConfig = new SiteConfigService(ctx.env.DB, ctx.env)
  const { siteName, supportEmail } = await siteConfig.load()

  const { subject, html, text } = renderPasswordChangedEmail({
    user: { firstName: user.first_name ?? undefined, email: user.email },
    siteName,
    supportEmail,
    when: event.timestamp,
  })

  const result = await getEmailService().send({
    to: user.email,
    subject,
    html,
    text,
    purpose: 'password_changed',
    userId: user.id,
    templateName: 'auth.password-changed',
    templateVariables: {
      firstName: user.first_name,
      siteName,
      when: event.timestamp,
    },
  })

  if (result.status === 'failed_at_send') {
    console.warn('[email-plugin] auth:password-reset:completed: send failed', {
      event: event.type,
      purpose: 'password_changed',
      userId: event.userId,
      errorCode: result.errorCode,
      errorMessage: result.errorMessage,
    })
  }
}
