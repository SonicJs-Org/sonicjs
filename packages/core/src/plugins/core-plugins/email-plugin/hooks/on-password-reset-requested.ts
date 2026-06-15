/**
 * `auth:password-reset:requested` hook handler — sends the password-reset
 * email. Factory pattern: closes over `env` from the boot context.
 *
 * Adapted from mmcintosh/sonicjs-infowall-merge for our hook signature
 * and our EmailMessage/SendResult shapes.
 *
 * Note: our AuthPasswordResetRequestedPayload does not carry `expiresAt`.
 * We default to 1 hour from invocation time; add the field to the payload
 * when the auth layer exposes it.
 */
import type { AuthPasswordResetRequestedPayload } from '../../../hooks/catalog'
import { getEmailService } from '../../../../services/email/email-service-singleton'
import { SiteConfigService } from '../services/site-config.service'
import { renderPasswordResetEmail } from '../templates/password-reset'

const DEFAULT_EXPIRY_MS = 60 * 60 * 1000 // 1 hour

interface UserRow {
  id: string
  email: string
  first_name: string | null
}

export function makeOnPasswordResetRequested(env: Record<string, unknown>) {
  const db = env.DB as D1Database
  return async (payload: AuthPasswordResetRequestedPayload): Promise<void> => {
    const user = await db
      .prepare('SELECT id, email, first_name FROM users WHERE id = ?')
      .bind(payload.user.id)
      .first<UserRow>()

    if (!user) {
      console.warn('[email-plugin] auth:password-reset:requested: user not found', {
        userId: payload.user.id,
      })
      return
    }

    const siteConfig = new SiteConfigService(db, env as { PUBLIC_URL?: string })
    const { siteName, siteUrl } = await siteConfig.load()
    const resetLink = siteConfig.buildResetLink(siteUrl, payload.resetToken)

    const { subject, html, text } = renderPasswordResetEmail({
      user: { firstName: user.first_name ?? undefined, email: user.email },
      resetLink,
      expiresAt: Date.now() + DEFAULT_EXPIRY_MS,
      siteName,
    })

    const result = await getEmailService().send({
      to: user.email,
      subject,
      html,
      text,
      flow: 'password_reset',
    })

    if (!result.ok) {
      console.warn('[email-plugin] auth:password-reset:requested: send failed', {
        userId: payload.user.id,
        error: result.error,
      })
    }
  }
}
