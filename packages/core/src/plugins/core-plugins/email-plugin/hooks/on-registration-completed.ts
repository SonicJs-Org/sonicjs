/**
 * `auth:registration:completed` hook handler — sends the welcome email.
 *
 * Returns a factory so the caller (onBoot) can close over `env` from the
 * boot context, giving the handler access to D1 + env bindings without
 * threading them through the typed hook payload.
 *
 * Adapted from mmcintosh/sonicjs-infowall-merge for our hook signature
 * (payload, context) and our EmailMessage/SendResult shapes.
 */
import type { AuthRegistrationCompletedPayload } from '../../../hooks/catalog'
import { getEmailService } from '../../../../services/email/email-service-singleton'
import { SiteConfigService } from '../services/site-config.service'
import { renderWelcomeEmail } from '../templates/welcome'

interface UserRow {
  id: string
  email: string
  first_name: string | null
}

export function makeOnRegistrationCompleted(env: Record<string, unknown>) {
  const db = env.DB as D1Database
  return async (payload: AuthRegistrationCompletedPayload): Promise<void> => {
    // When verificationRequired is on, the welcome email is sent after the
    // user clicks the verification link — not here. Fail-open on missing table.
    try {
      const setting = await db
        .prepare(
          `SELECT value FROM settings
           WHERE category = 'general' AND key = 'verificationRequired'`,
        )
        .first<{ value: string }>()
      if (setting?.value === 'true') return
    } catch {
      // Pre-migration DB — fall through and send welcome.
    }

    const user = await db
      .prepare('SELECT id, email, first_name FROM users WHERE id = ?')
      .bind(payload.user.id)
      .first<UserRow>()

    if (!user) {
      console.warn('[email-plugin] auth:registration:completed: user not found', {
        userId: payload.user.id,
      })
      return
    }

    const siteConfig = new SiteConfigService(db, env as { PUBLIC_URL?: string })
    const { siteName, siteUrl } = await siteConfig.load()

    const { subject, html, text } = renderWelcomeEmail({
      user: { firstName: user.first_name ?? undefined, email: user.email },
      siteName,
      loginUrl: siteConfig.buildLoginUrl(siteUrl),
    })

    const result = await getEmailService().send({
      to: user.email,
      subject,
      html,
      text,
      flow: 'welcome',
    })

    if (!result.ok) {
      console.warn('[email-plugin] auth:registration:completed: send failed', {
        userId: payload.user.id,
        error: result.error,
      })
    }
  }
}
