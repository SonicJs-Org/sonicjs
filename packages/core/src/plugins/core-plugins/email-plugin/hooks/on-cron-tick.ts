/**
 * `cron:tick` hook handler — runs the email-reconciliation cron.
 *
 * Filters on `event.hookFamily !== 'email-reconciliation'` (early return)
 * per the manifest declaration. Other plugins' cron families are ignored.
 *
 * Defensive credential check (per §0 trigger 12 in the dispatch): if
 * `ctx.env.EMAIL_API_TOKEN` or `ctx.env.CF_ZONE_ID` is undefined at the
 * cron's execution time (secrets rotated or never persisted), this handler
 * logs a structured warning and returns without throwing. The reconciliation
 * cron is best-effort — if credentials are gone, deliveries still get
 * recorded as `'submitted'`; the dashboard just shows degraded data until
 * credentials are re-provisioned.
 *
 * Note: previously used `CF_ACCOUNT_ID` because the hub spec specified an
 * account-scoped GraphQL dataset that does not exist in CF's schema. The
 * correct outbound-email dataset is `zones.zoneEmailSendingAdaptive`, so
 * the cron now requires `CF_ZONE_ID` instead. See #701 final resolution.
 *
 * Failures of the reconciliation itself (GraphQL down, partial row update
 * errors) are surfaced in the `RunOutcome` returned by
 * `ReconciliationService.run` — this handler logs them but doesn't throw.
 */
import type { CronTickEvent } from '../../../cron'
import { CfGraphqlClient } from '../services/cf-graphql-client'
import { EmailLogService } from '../services/email-log.service'
import { EmailSettingsService } from '../services/settings.service'
import { ReconciliationService } from '../services/reconciliation'

export const onCronTick = async (event: CronTickEvent, ctx: { env?: Record<string, unknown> }): Promise<void> => {
  if (event.hookFamily !== 'email-reconciliation') {
    return
  }

  // Defensive credential check — both bindings declared optional in
  // global.d.ts (Phase B.4.5 step 20a); the cron skips gracefully if either
  // is missing rather than crashing. The D1 fallback for the token remains
  // (settings admin UI can supply it); zoneId has no D1 fallback yet — add
  // a `cfZoneId` field to EmailSettings as a follow-up if per-tenant zone
  // overrides become needed (today CF_ZONE_ID is provisioned per env at
  // deploy time, which is the normal case).
  const env = ctx.env ?? {}
  let zoneId = env.CF_ZONE_ID as string | undefined
  let apiToken = env.EMAIL_API_TOKEN as string | undefined

  if (!apiToken) {
    try {
      const s = await new EmailSettingsService(env.DB as D1Database).load()
      if (!apiToken && s.cfEmailApiToken) {
        apiToken = s.cfEmailApiToken
        console.debug('[email-plugin] reconciliation cron: EMAIL_API_TOKEN read from D1 settings')
      }
    } catch { /* D1 unavailable — fall through */ }
  }

  if (!zoneId || !apiToken) {
    console.warn(
      '[email-plugin] reconciliation cron skipped: CF GraphQL credentials missing ' +
        '(set via wrangler secrets — CF_ZONE_ID is required for zoneEmailSendingAdaptive)',
      {
        haveZoneId: Boolean(zoneId),
        haveApiToken: Boolean(apiToken),
      },
    )
    return
  }

  try {
    const graphql = new CfGraphqlClient(zoneId, apiToken)
    const emailLog = new EmailLogService(env.DB as D1Database)
    const reconciliation = new ReconciliationService(graphql, emailLog)

    const outcome = await reconciliation.run({ windowHours: 24 })

    if (outcome.status === 'graphql_error') {
      console.warn('[email-plugin] reconciliation cron: GraphQL error', {
        error: outcome.error,
      })
    } else if (outcome.status === 'ok') {
      console.log('[email-plugin] reconciliation cron: ok', {
        graphqlRowCount: outcome.graphqlRowCount,
        updatedRowCount: outcome.updatedRowCount,
      })
    } else if (outcome.status === 'no_rows') {
      // Issue #701 observability — previously silently swallowed, which made
      // "CF returned empty" indistinguishable from "cron never fired" in tail.
      console.log('[email-plugin] reconciliation cron: no_rows (CF returned 0 rows for 24h window)')
    }
  } catch (err) {
    /* v8 ignore next 4 -- outer defensive catch; recoverable errors land in RunOutcome */
    console.error('[email-plugin] reconciliation cron: unexpected error', {
      error: err instanceof Error ? err.message : String(err),
    })
  }
}
