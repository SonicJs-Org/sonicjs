/**
 * ReconciliationService — orchestrates the 5-minute reconciliation cron.
 *
 * Per Q3 resolution (LOCKED): the GraphQL query bounds to the last 24h of
 * sends, and the D1 UPDATE filters on `delivery_synced_at IS NULL` for
 * idempotency + late-bounce-signal capture (re-running over the same
 * window updates rows that have transitioned state but doesn't double-
 * sync rows already terminal).
 *
 * Maps GraphQL `status` values to `email_log.delivery_state` values:
 *   - `'delivered'` → `'delivered'`
 *   - `'deliveryFailed'` → `'delivery_failed'`
 *   - `'bounced'` → `'bounced'`
 *   - `'rejected'` → `'rejected'`
 *
 * Failure handling per hub spec §8: log + retry on next tick. Don't crash
 * the cron if GraphQL is briefly down. The `run()` method catches and
 * returns a structured outcome so the hook handler can log without
 * propagating.
 */
import type { CfGraphqlClient } from './cf-graphql-client'
import type { EmailLogService } from './email-log.service'
import type { GraphQLActivityLogRow, EmailLogRow } from '../types'

type DeliveryState = NonNullable<EmailLogRow['delivery_state']>

export interface RunInput {
  /** Window length in hours. Defaults to 24 per Q3 LOCKED. */
  windowHours?: number
  /** Optional override for "now"; useful for deterministic tests. */
  now?: number
}

export interface RunOutcome {
  readonly status: 'ok' | 'graphql_error' | 'no_rows'
  readonly graphqlRowCount: number
  readonly updatedRowCount: number
  readonly error?: string
}

export function mapGraphQLStatusToDeliveryState(
  status: GraphQLActivityLogRow['status'],
): DeliveryState {
  switch (status) {
    case 'delivered':
      return 'delivered'
    case 'deliveryFailed':
      return 'delivery_failed'
    case 'bounced':
      return 'bounced'
    case 'rejected':
      return 'rejected'
  }
}

export class ReconciliationService {
  constructor(
    private readonly graphql: CfGraphqlClient,
    private readonly emailLog: EmailLogService,
  ) {}

  async run(input: RunInput = {}): Promise<RunOutcome> {
    const windowHours = input.windowHours ?? 24
    const nowMs = input.now ?? Date.now()
    const endSeconds = Math.floor(nowMs / 1000)
    const startSeconds = endSeconds - windowHours * 60 * 60

    let rows: readonly GraphQLActivityLogRow[]
    try {
      rows = await this.graphql.queryEmailSends({ startSeconds, endSeconds })
    } catch (err) {
      return {
        status: 'graphql_error',
        graphqlRowCount: 0,
        updatedRowCount: 0,
        error: err instanceof Error ? err.message : /* v8 ignore next */ String(err),
      }
    }

    if (rows.length === 0) {
      return { status: 'no_rows', graphqlRowCount: 0, updatedRowCount: 0 }
    }

    let updated = 0
    for (const row of rows) {
      try {
        await this.emailLog.updateDeliveryState({
          cloudflareMessageId: row.messageId,
          deliveryState: mapGraphQLStatusToDeliveryState(row.status),
          errorMessage: row.errorCause,
          syncedAt: nowMs,
        })
        updated++
      } catch (err) {
        // Per-row failures don't crash the run — the next tick retries.
        console.error('[email-plugin] reconciliation row update failed', {
          messageId: row.messageId,
          error: err instanceof Error ? err.message : /* v8 ignore next */ String(err),
        })
      }
    }

    return { status: 'ok', graphqlRowCount: rows.length, updatedRowCount: updated }
  }
}
