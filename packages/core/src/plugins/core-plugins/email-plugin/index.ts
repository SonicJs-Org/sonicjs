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

export const emailPluginV3 = definePlugin({
  id: 'email',
  version: '1.0.0',
  name: 'Email',
  capabilities: ['email:send', 'cron:register', 'hooks.auth:subscribe'] as const,
  crons: [{ schedule: '*/5 * * * *', hookFamily: 'email-reconciliation' }],
  register: (app) => {
    app.route('/admin/email', adminRoutes)
  },
  onBoot(ctx) {
    const env = (ctx.env ?? {}) as Record<string, unknown>
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
