/**
 * `auth:registration:completed` hook handler — sends the welcome email.
 *
 * Tight scope (design doc §9, scope memo §6.5 Decision 5 separation of
 * concerns): D1 user lookup + render via `renderWelcomeEmail` +
 * `getEmailService().send` + structured warn on failure. This handler does
 * NOT write to any audit-log primitive (that's a separate subscriber's
 * job).
 *
 * The dispatcher (`routes/auth.ts`) is fire-and-forget via
 * `c.executionCtx?.waitUntil(...)`; this handler's throw would land in
 * the HookSystem's internal try/catch (failure is logged, never propagates
 * to the client request).
 */
import type { SonicHookHandler } from '../../../sdk/types'
import { getEmailService } from '../../../../services/email-service-singleton'
import { SiteConfigService } from '../services/site-config.service'
import { renderWelcomeEmail } from '../templates/welcome'

interface UserRow {
  id: string
  email: string
  first_name: string | null
}

export const onRegistrationCompleted: SonicHookHandler<'auth:registration:completed'> = async (
  ctx,
  event,
) => {
  // PR-EV G2: when general.verificationRequired is on, the welcome email
  // is sent by the /auth/verify-email handler after the user clicks the
  // verification link. Short-circuit here so we don't email a "your
  // account is ready, sign in" message to someone who can't actually
  // sign in until they verify. Fail-open on missing settings table /
  // missing row (pre-migration DB) — preserves legacy behavior.
  try {
    const setting = await ctx.env.DB
      .prepare(
        `SELECT value FROM settings
         WHERE category = 'general' AND key = 'verificationRequired'`,
      )
      .first<{ value: string }>()
    if (setting?.value === 'true') {
      return
    }
  } catch {
    // Pre-migration DB — fall through and send welcome.
  }

  const user = await ctx.env.DB
    .prepare('SELECT id, email, first_name FROM users WHERE id = ?')
    .bind(event.userId)
    .first<UserRow>()

  if (!user) {
    console.warn('[email-plugin] auth:registration:completed: user not found', {
      userId: event.userId,
    })
    return
  }

  const siteConfig = new SiteConfigService(ctx.env.DB, ctx.env)
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
    purpose: 'welcome',
    userId: user.id,
    templateName: 'auth.welcome',
    templateVariables: {
      firstName: user.first_name,
      siteName,
      registrationSource: event.registrationSource,
    },
  })

  if (result.status === 'failed_at_send') {
    console.warn('[email-plugin] auth:registration:completed: send failed', {
      event: event.type,
      purpose: 'welcome',
      userId: event.userId,
      errorCode: result.errorCode,
      errorMessage: result.errorMessage,
    })
  }
}
