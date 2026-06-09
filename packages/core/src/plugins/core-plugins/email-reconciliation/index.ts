/**
 * Email reconciliation cron plugin
 *
 * Defines the `email_log` document type (owned here, registered in document-types-seed.ts)
 * and provides an hourly cron that backfills `deliveryState` for sent emails by calling
 * provider.reconcile?() when the active transport supports it.
 *
 * Email log entries are stored as documents (type_id='email_log') in the documents table —
 * no separate email_log table. Each entry is a single draft-only document (maxVersionsPerRoot=1,
 * never published). The cron updates delivery state by updating the document's data JSON.
 */

import { z } from 'zod'
import { definePlugin } from '../../sdk/define-plugin'
import { getEmailService, hasEmailService } from '../../../services/email/email-service-singleton'
import type { QueryableField } from '../../../schemas/document'

/** Maximum rows to reconcile per cron run. */
const BATCH_SIZE = 100

/**
 * The email_log document type definition.
 * Exported so document-types-seed.ts can register it at bootstrap time (before any
 * email send could occur — before plugin onBoot runs).
 */
export const EMAIL_LOG_DOCUMENT_TYPE = {
  id: 'email_log',
  name: 'email_log',
  displayName: 'Email Log',
  description: 'Record of every email send attempt. Owned by the email plugin. PII: toEmail.',
  source: 'system' as const,
  schema: z.record(z.string(), z.unknown()),
  settings: {
    // Admin-only — email logs are internal records, not publishable content.
    baseGrants: {
      admin: ['read', 'delete', 'manage'] as ('read' | 'create' | 'update' | 'delete' | 'publish' | 'manage')[],
    },
    // Immutable log entries: one version, never a new draft after creation.
    maxVersionsPerRoot: 1,
    pii: true,
  },
  queryableFields: [
    { name: 'status',   kind: 'scalar' as const, type: 'text' as const, column: 'q_email_status'   },
    { name: 'provider', kind: 'scalar' as const, type: 'text' as const, column: 'q_email_provider' },
    { name: 'flow',     kind: 'scalar' as const, type: 'text' as const, column: 'q_email_flow'     },
    { name: 'toEmail',  kind: 'scalar' as const, type: 'text' as const, column: 'q_email_to'       },
  ] satisfies QueryableField[],
}

export const emailReconciliationPlugin = definePlugin({
  id: 'email-reconciliation',
  version: '1.0.0',
  description:
    'Hourly cron that backfills email delivery state from provider status APIs. ' +
    'Only active for providers that implement EmailProvider.reconcile().',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },
  capabilities: ['email:send', 'db:email_log'],
  sonicjsVersionRange: '>=2.18.0',

  crons: [
    {
      // Every hour. Add `0 * * * *` to wrangler.toml [triggers] crons to activate in production.
      schedule: '0 * * * *',
      hookFamily: 'email-reconciliation',
    },
  ],

  async onCronTick(event, ctx) {
    if (event.hookFamily !== 'email-reconciliation') return

    const db = ctx.env?.DB as D1DatabaseLike | undefined
    if (!db) {
      console.warn('[email-reconciliation] No DB binding in cron env — skipping.')
      return
    }

    if (!hasEmailService()) {
      console.warn('[email-reconciliation] EmailService not initialized — skipping.')
      return
    }

    const emailService = getEmailService()

    // Fetch unreconciled email_log documents — current drafts where status=sent,
    // provider_id exists in data, and deliveryState is not yet set.
    let rows: Array<{ id: string; root_id: string; data: string }> = []
    try {
      const result = await db
        .prepare(
          `SELECT id, root_id, data FROM documents
           WHERE type_id = 'email_log'
             AND tenant_id = 'default'
             AND is_current_draft = 1
             AND deleted_at IS NULL
             AND q_email_status = 'sent'
             AND json_extract(data, '$.providerId') IS NOT NULL
             AND json_extract(data, '$.deliveryState') IS NULL
           LIMIT ?`
        )
        .bind(BATCH_SIZE)
        .all()
      rows = (result.results ?? []) as any[]
    } catch (err) {
      console.error('[email-reconciliation] Failed to query email_log documents:', err)
      return
    }

    if (rows.length === 0) {
      console.log('[email-reconciliation] No unreconciled rows — nothing to do.')
      return
    }

    // Build EmailLogRow-shaped objects for the provider.
    const logRows = rows.map((r) => {
      const d = r.data ? JSON.parse(r.data) : {}
      return {
        id: r.root_id,
        provider_id: d.providerId ?? null,
        provider: d.provider ?? '',
        status: d.status ?? 'sent',
        delivery_state: d.deliveryState ?? null,
      }
    })

    const updates = await emailService.reconcileDelivery(logRows)

    if (!updates || updates.length === 0) {
      console.log(
        `[email-reconciliation] Provider "${emailService.getProviderName()}" ` +
          `returned no updates for ${rows.length} rows.`
      )
      return
    }

    // Write delivery states back into the document data JSON.
    const now = Math.floor(Date.now() / 1000)
    let updated = 0
    // eslint-disable-next-line @typescript-eslint/naming-convention
    for (const { id: rootId, delivery_state } of updates) {
      const row = rows.find((r) => r.root_id === rootId)
      if (!row) continue
      try {
        const d = row.data ? JSON.parse(row.data) : {}
        d.deliveryState = delivery_state
        d.deliverySyncedAt = now
        await db
          .prepare(
            `UPDATE documents SET data = ?, updated_at = ?
             WHERE root_id = ? AND tenant_id = 'default' AND is_current_draft = 1`
          )
          .bind(JSON.stringify(d), now, rootId)
          .run()
        updated++
      } catch (err) {
        console.error(`[email-reconciliation] Failed to update document ${rootId}:`, err)
      }
    }

    console.log(
      `[email-reconciliation] Reconciled ${updated}/${rows.length} email_log documents ` +
        `via provider "${emailService.getProviderName()}".`
    )
  },
})

/** Minimal D1 interface (avoids hard @cloudflare/workers-types dep in this file). */
interface D1DatabaseLike {
  prepare(sql: string): {
    bind(...args: unknown[]): {
      run(): Promise<unknown>
      all(): Promise<{ results: unknown[] }>
    }
  }
}
