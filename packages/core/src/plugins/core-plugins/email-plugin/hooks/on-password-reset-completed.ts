/**
 * `auth:password-reset:completed` hook handler — sends the password-changed
 * confirmation email. Factory pattern: closes over `env` from boot context.
 *
 * Adapted from mmcintosh/sonicjs-infowall-merge for our hook signature
 * and our EmailMessage/SendResult shapes.
 */
import type { AuthPasswordResetCompletedPayload } from '../../../hooks/catalog'
import { getEmailService } from '../../../../services/email/email-service-singleton'
import { SiteConfigService } from '../services/site-config.service'
import { renderPasswordChangedEmail } from '../templates/password-changed'

interface UserRow {
  id: string
  email: string
  first_name: string | null
}

export function makeOnPasswordResetCompleted(env: Record<string, unknown>) {
  const db = env.DB as D1Database
  return async (payload: AuthPasswordResetCompletedPayload): Promise<void> => {
    const user = await db
      .prepare('SELECT id, email, first_name FROM users WHERE id = ?')
      .bind(payload.user.id)
      .first<UserRow>()

    if (!user) {
      console.warn('[email-plugin] auth:password-reset:completed: user not found', {
        userId: payload.user.id,
      })
      return
    }

    const siteConfig = new SiteConfigService(db, env as { PUBLIC_URL?: string })
    const { siteName, supportEmail } = await siteConfig.load()

    const { subject, html, text } = renderPasswordChangedEmail({
      user: { firstName: user.first_name ?? undefined, email: user.email },
      siteName,
      supportEmail,
      when: Date.now(),
    })

    const result = await getEmailService().send({
      to: user.email,
      subject,
      html,
      text,
      flow: 'password_changed',
    })

    if (!result.ok) {
      console.warn('[email-plugin] auth:password-reset:completed: send failed', {
        userId: payload.user.id,
        error: result.error,
      })
    }
  }
}
