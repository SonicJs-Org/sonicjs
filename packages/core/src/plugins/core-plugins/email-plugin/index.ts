/**
 * v3 email-plugin entrypoint (PR-E Phase B, 2026-05-13).
 *
 * Replaces the legacy PluginBuilder-based plugin with a `definePlugin` v3
 * SonicPlugin shape. The plugin:
 *
 *   - Subscribes to three auth lifecycle events (`auth:registration:completed`,
 *     `auth:password-reset:requested`, `auth:password-reset:completed`) +
 *     the cron family `email-reconciliation` (via `cron:tick`).
 *   - Mounts admin routes at `/admin/email/*` (POST /settings + POST /test)
 *     via synchronous `register(app)` (Phase B.0 Option A constraint —
 *     register MUST run at construction time before Hono's matcher locks).
 *   - Declares one cron schedule (every 5 minutes) for the reconciliation
 *     family.
 *
 * The host (`createSonicJSApp`) constructs `EmailServiceImpl` lazily on
 * first request and calls `setEmailService(...)`. This plugin's handlers
 * consume the service via `getEmailService()` from the singleton.
 *
 * Note: the legacy `emailPlugin` + `createEmailPlugin` exports are REMOVED
 * — `createSonicJSApp` no longer imports them; `routes/admin-plugins.ts`
 * reads the manifest.json directly via its standard plugin enumeration.
 */
import { definePlugin } from '../../sdk'
import { adminRoutes } from './routes/admin'
import { onRegistrationCompleted } from './hooks/on-registration-completed'
import { onPasswordResetRequested } from './hooks/on-password-reset-requested'
import { onPasswordResetCompleted } from './hooks/on-password-reset-completed'
import { onCronTick } from './hooks/on-cron-tick'

export const emailPluginV3 = definePlugin({
  id: 'email',
  version: '1.0.0',
  displayName: 'Email',
  capabilities: ['email:send', 'hooks.cron:register', 'hooks.auth:register'] as const,
  crons: [{ schedule: '*/5 * * * *', hookFamily: 'email-reconciliation' }],
  register: (app) => {
    app.route('/admin/email', adminRoutes)
  },
  hooks: {
    'auth:registration:completed': onRegistrationCompleted,
    'auth:password-reset:requested': onPasswordResetRequested,
    'auth:password-reset:completed': onPasswordResetCompleted,
    'cron:tick': onCronTick,
  },
})
