/**
 * two-factor-auth — TOTP second factor with single-use backup codes.
 *
 * ── What lives where ──
 * This plugin owns the SURFACE and the POLICY: the enrolment page, the login challenge page, the
 * `/complete` session upgrade, and the settings that feed the policy knobs. It does NOT own the Better Auth plugin
 * instance — `auth/config.ts` composes `twoFactor()`, because BA is constructed per request
 * by a synchronous `createAuth()` that a plugin's `register(app)` cannot reach into.
 *
 * The policy is read once per isolate here in `onBoot` and handed to `createAuth` through the
 * module-level cache in `auth/two-factor-settings.ts` — see that file for why the getter has
 * to be synchronous.
 *
 * ── Two mounts, deliberately asymmetric ──
 *   - `/admin/two-factor` — enrolment. Behind the global `/admin/*` requireAuth +
 *     requireRbac('portal','access') gate, plus a local requireAuth and a deactivate→404 gate.
 *   - `/auth/two-factor`  — the login challenge. Mounted outside `/admin/*` and NOT gated,
 *     because it must be reachable WITHOUT a session: at challenge time the caller has proven
 *     a password and nothing else, and Better Auth has already deleted the session cookie it
 *     briefly created. That is a decision, not an oversight — a challenge page that 404s when
 *     the plugin is deactivated would strand every enrolled user mid-login, which is exactly
 *     the silent-downgrade failure the unconditional composition in `auth/config.ts` exists to
 *     prevent.
 *
 * ── Prefixes ──
 * Enrolment is `/admin/two-factor`, not under `/admin/plugins/`. Plugin routes are registered
 * ahead of `adminPluginRoutes` and Hono's first match wins, so mounting at
 * `/admin/plugins/two-factor-auth` would make THIS sub-app shadow the generic plugin-detail page
 * for this plugin (`/admin/plugins/:id`). Keeping enrolment on its own prefix leaves both the
 * detail page and the schema-driven settings form at
 * `/admin/plugins/two-factor-auth/configure` untouched. (`api-docs` does mount under
 * `/admin/plugins/api-docs` and accepts that trade; a security control gets its own prefix.)
 *
 * `/auth/two-factor` does not collide with Better Auth: every BA two-factor endpoint is
 * `POST /auth/two-factor/<action>` (enable, disable, verify-totp, verify-backup-code,
 * get-totp-uri, generate-backup-codes), and there is no bare `/two-factor` route. Hono
 * flattens `app.route()` sub-apps into the parent router, so the POSTs fall through to the
 * `/auth/*` catch-all that serves BA.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { twoFactorAdminRoutes } from './routes'
import { loadTwoFactorPolicy, TWO_FACTOR_PLUGIN_ID } from '../../../auth/two-factor-settings'
import {
  ensureTwoFactorLockoutColumns,
  ensureTwoFactorRequiredColumn,
} from '../../../services/migrations'
import type { D1Database } from '@cloudflare/workers-types'
import manifest from './manifest.json'

// Heroicons "lock-closed" (matches the manifest adminMenu icon).
const TWO_FACTOR_ICON = `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>`

export const twoFactorAuthPlugin = definePlugin({
  id: TWO_FACTOR_PLUGIN_ID,
  version: manifest.version,
  name: manifest.name,
  description: manifest.description,
  sonicjsVersionRange: '^3.0.0',
  author: { name: manifest.author },

  /**
   * Only the ENROLMENT surface. The login challenge (`/auth/two-factor`) is mounted by core in
   * app.ts, unconditionally — see the comment there. Mounting it here too would put it behind
   * `config.plugins.disableAll`, which is what previously 404'd enrolled users out of an app whose
   * Better Auth still demanded their second factor.
   */
  register(app) {
    app.route('/admin/two-factor', twoFactorAdminRoutes)
  },

  /**
   * Three jobs, all idempotent.
   *
   * 0. Repair the columns migrations 0006 and 0007 add — `auth_two_factor`'s lockout pair and
   *    `auth_user.two_factor_required` — if those migrations never ran. Both also live in
   *    `MigrationService.ensureSchemaCompatibility()`, but the bootstrap middleware skips that
   *    entirely once the `_sonicjs_bootstrap_<version>` KV marker is set (24h TTL) — so on most
   *    cold isolates it would not run at all. `onBoot` runs on every isolate, which is what makes
   *    the repair the belt-and-braces the migration comments claim it is. The 0004 repair matters
   *    most: the enrolment-enforcement middleware reads that column on every admin request, so a
   *    database missing it would 500 the whole portal rather than degrade.
   *
   * 1. Make sure the plugin's own document row exists. `PluginBootstrapService` only *checks*
   *    plugins whose name starts with `core-` when deciding whether a bootstrap is needed, so
   *    on a database that was already bootstrapped before this plugin existed, nothing would
   *    ever install it — and `isPluginActive()` would then 404 the enrolment page forever.
   *    Create-if-missing only: an existing row is returned untouched, so an admin's
   *    deactivation is never silently undone by the next cold isolate.
   *
   * 2. Load the policy into the isolate cache that `createAuth` reads synchronously. `boot()`
   *    is registered ahead of the session middleware in app.ts and awaited, so by the first
   *    `createAuth()` of the isolate the real settings are in place; until then the strict
   *    defaults apply.
   */
  async onBoot(ctx) {
    const db = (ctx.env as { DB?: D1Database } | undefined)?.DB
    if (!db) return

    await ensureTwoFactorLockoutColumns(db)
    await ensureTwoFactorRequiredColumn(db)

    try {
      const { PluginService } = await import('../../../services/plugin-service')
      const service = new PluginService(db)
      if (!(await service.getPlugin(TWO_FACTOR_PLUGIN_ID))) {
        await service.installPlugin({
          id: TWO_FACTOR_PLUGIN_ID,
          name: TWO_FACTOR_PLUGIN_ID,
          display_name: manifest.name,
          description: manifest.description,
          version: manifest.version,
          author: manifest.author,
          category: manifest.category,
          icon: manifest.iconEmoji,
          // `false`, matching what PluginBootstrapService writes on the greenfield path
          // (`is_core: plugin.name.startsWith("core-")` — this id does not). Passing
          // `manifest.is_core` here would give the SAME plugin a different `isCore` depending on
          // which path installed it, which `uninstallPlugin`'s core guard reads.
          // `manifest.is_core: true` still does its real job — it is what puts this plugin in
          // BOOTSTRAP_PLUGIN_IDS on a fresh install.
          is_core: false,
          settings: manifest.defaultSettings,
          permissions: Object.keys(manifest.permissions),
        })
        // installPlugin wrote a row this isolate may already have cached as inactive.
        const { invalidatePluginStatusCache } = await import('../../../middleware/plugin-middleware')
        invalidatePluginStatusCache(TWO_FACTOR_PLUGIN_ID)
        console.log('[two-factor] registered plugin row (was missing)')
      }
    } catch (e) {
      // Non-fatal: the surface 404s until the row exists, but verification (auth/config.ts) is
      // never gated on plugin status, so an enrolled user can still sign in.
      console.error('[two-factor] plugin row registration failed', e)
    }

    try {
      await loadTwoFactorPolicy(db)
    } catch (e) {
      // Never fail boot for a settings read — defaults are the safe end of every knob.
      console.error('[two-factor] policy load failed during onBoot; using defaults', e)
    }
  },

  menu: [
    { label: 'Two-Factor Auth', path: '/admin/two-factor', icon: TWO_FACTOR_ICON, order: 86 },
  ],

  /**
   * Policy settings, rendered automatically at `/admin/plugins/two-factor-auth/configure` (the
   * generic `/:id/configure` form, so the path carries the full plugin id) and persisted by
   * `PluginService.updatePluginSettings` into the plugin document — the same place
   * `loadTwoFactorPolicy` reads, so this is not save-nowhere chrome.
   *
   * Bounds are duplicated in `normalizeTwoFactorPolicy`, which clamps on read. The form is a
   * hint; the clamp is the guarantee.
   */
  configSchema: {
    issuer: {
      type: 'string',
      label: 'Issuer name',
      default: 'SonicJS',
      description: "Label shown beside the account in the user's authenticator app.",
      maxLength: 64,
    },
    maxFailedAttempts: {
      type: 'number',
      label: 'Failed attempts before lockout',
      default: 5,
      min: 3,
      max: 10,
      description:
        'Consecutive failed second-factor verifications before the account is locked. Per-account, so rotating IPs does not help an attacker.',
    },
    lockoutDurationSeconds: {
      type: 'number',
      label: 'Lockout duration (seconds)',
      default: 900,
      min: 300,
      max: 3600,
      description: 'How long the second-factor lockout lasts.',
    },
    backupCodeCount: {
      type: 'number',
      label: 'Backup code count',
      default: 10,
      min: 5,
      max: 20,
      description:
        'Single-use codes minted at enrolment. With no external identity provider these are the only route back in if the authenticator device is lost.',
    },
  },

  activate: async () => console.log('[TwoFactorAuth] Plugin activated'),
  deactivate: async () => console.log('[TwoFactorAuth] Plugin deactivated'),
})

export function createTwoFactorAuthPlugin() {
  return twoFactorAuthPlugin
}

export { twoFactorAdminRoutes, twoFactorChallengeRoutes } from './routes'
// Mounted by core in app.ts, NOT by `register()` above — see recovery.ts for why both the reset
// routes and the enforcement middleware have to sit outside this plugin's deactivate→404 gate
// and outside plugin registration order.
export {
  twoFactorRecoveryRoutes,
  enforceTwoFactorEnrolment,
  guardRequiredSecondFactorDisable,
  resetUserTwoFactor,
  isTwoFactorRequired,
  RECOVERY_PREFIX,
  ENROLMENT_PATH,
  BA_DISABLE_PATH,
} from './recovery'
export default twoFactorAuthPlugin
