/**
 * v3 email-plugin entrypoint (PR-E Phase B, 2026-05-13).
 *
 * Replaces the legacy PluginBuilder-based plugin with a `definePlugin` v3
 * SonicPlugin shape. The plugin:
 *
 *   - Subscribes to three auth lifecycle events (`auth:registration:completed`,
 *     `auth:password-reset:requested`, `auth:password-reset:completed`) via
 *     `onBoot`, which closes over `ctx.env` so handlers have D1 + env access.
 *   - Mounts admin routes at `/admin/email/*` via synchronous `register(app)`.
 *   - Declares one cron schedule (every 5 minutes) for the reconciliation
 *     family, handled via `onCronTick`.
 *
 * Hook handlers are factory functions (`makeOn*`) that capture env at boot
 * time — required because our TypedHookContext doesn't carry env, but
 * DefinedPluginContext does.
 */
import { definePlugin } from '../../sdk'
import { adminRoutes } from './routes/admin'
import { makeOnRegistrationCompleted } from './hooks/on-registration-completed'
import { makeOnPasswordResetRequested } from './hooks/on-password-reset-requested'
import { makeOnPasswordResetCompleted } from './hooks/on-password-reset-completed'
import { onCronTick } from './hooks/on-cron-tick'
import { EmailSettingsService } from './services/settings.service'
import { setEmailService, hasEmailService } from '../../../services/email/email-service-singleton'
import { EmailService } from '../../../services/email/email-service'
import { resolveEmailProvider } from '../../../services/email/resolve-provider'
import { CloudflareEmailProvider } from './services/cf-email-provider'
import { DocumentTypeRegistry } from '../../../services/document-type-registry'
import { z } from 'zod'

export const emailPluginV3 = definePlugin({
  id: 'email',
  version: '1.0.0',
  name: 'Email',
  capabilities: ['email:send', 'cron:register', 'hooks.auth:subscribe'] as const,
  crons: [{ schedule: '*/5 * * * *', hookFamily: 'email-reconciliation' }],
  register: (app) => {
    app.route('/admin/email', adminRoutes)
  },
  async onBoot(ctx) {
    const env = (ctx.env ?? {}) as Record<string, unknown>
    const db = env.DB as D1Database | undefined

    // Register email_log document type (FK required by email-service writeLog).
    if (db) {
      try {
        const typeRegistry = new DocumentTypeRegistry(db)
        await typeRegistry.register({
          id: 'email_log',
          name: 'email_log',
          displayName: 'Email Log',
          description: 'Transactional email send records',
          schema: z.object({}),
          pluginId: 'email',
          source: 'plugin',
          queryableFields: [],
          settings: {},
        })
      } catch {
        // document_types table may not exist in pre-migration dev — skip.
      }
    }

    // Wire up the EmailService based on provider selection.
    // Env vars always take precedence over DB settings.
    if (!hasEmailService()) {
      const settings = db ? await new EmailSettingsService(db).load() : {}

      const envResendKey = typeof env.RESEND_API_KEY === 'string' && env.RESEND_API_KEY ? env.RESEND_API_KEY : undefined
      const cfEmailBinding = env.EMAIL as { send: (...args: unknown[]) => Promise<unknown> } | undefined

      // Provider resolution order:
      // 1. RESEND_API_KEY env var → Resend (wins regardless of DB setting)
      // 2. DB provider=resend + resendApiKey → Resend
      // 3. CF EMAIL binding present + provider not forced to resend → CF Email
      // 4. Auto-detect from env / console fallback
      const serviceOpts = { defaultFrom: settings.fromEmail ?? '', defaultReplyTo: settings.replyTo, db: db as never }

      let provider
      if (envResendKey) {
        provider = resolveEmailProvider({ providerName: 'resend', env: { RESEND_API_KEY: envResendKey } })
      } else if (settings.provider === 'resend' && (settings.resendApiKey || envResendKey)) {
        provider = resolveEmailProvider({
          providerName: 'resend',
          env: { RESEND_API_KEY: envResendKey ?? settings.resendApiKey },
        })
      } else if (cfEmailBinding && settings.provider !== 'resend') {
        provider = new CloudflareEmailProvider(cfEmailBinding as never)
      } else {
        provider = resolveEmailProvider({ env: env as Record<string, unknown> })
      }

      setEmailService(new EmailService({ ...serviceOpts, provider }))
    }

    ctx.hooks.on('auth:registration:completed', makeOnRegistrationCompleted(env))
    ctx.hooks.on('auth:password-reset:requested', makeOnPasswordResetRequested(env))
    ctx.hooks.on('auth:password-reset:completed', makeOnPasswordResetCompleted(env))
  },
  onCronTick,
})

// Re-export template helpers for use by other plugins (e.g. OTP, magic-link)
export { renderWelcomeEmail } from './templates/welcome'
export { renderPasswordResetEmail } from './templates/password-reset'
export { renderPasswordChangedEmail } from './templates/password-changed'
export { renderOtpEmail } from './templates/otp'
export { renderVerificationEmail } from './templates/verification'
export { renderInvitationEmail } from './templates/invitation'
export { renderTestEmail } from './templates/test-email'
export { renderEmailLayout, renderPrimaryButton, renderTextLink, renderCodeBlock } from './templates/_layout'
export type { RenderedEmail } from './templates/welcome'
