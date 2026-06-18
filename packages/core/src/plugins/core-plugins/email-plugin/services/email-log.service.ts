/**
 * EmailLogService — D1 reads/writes for the `email_log` table (migration 106).
 *
 * Schema anchored to migration 106 + hub spec §3 (the hub spec is
 * authoritative). Two-column status model:
 *   - `status` — application-side outcome (`'submitted'` | `'failed_at_send'`)
 *   - `delivery_state` — Cloudflare-side outcome, populated later by the
 *     reconciliation cron (`NULL` until first sync; then
 *     `'delivered'` | `'bounced'` | `'rejected'` | `'delivery_failed'`)
 *
 * Write methods are write-once (rows are immutable at insert; the only
 * mutable column is `delivery_state` + `delivery_synced_at`, owned by
 * `updateDeliveryState`).
 */
import type { EmailLogRow } from '../types'

export interface InsertOnSubmitInput {
  id: string
  cloudflareMessageId: string | null
  recipient: string
  sender: string
  subject: string
  purpose: string
  templateName?: string
  templateVariablesJson?: string
  userId?: string
  contextType?: string
  contextId?: string
  tenantId?: string
  sentAt: number
}

export interface InsertOnFailedAtSendInput {
  id: string
  recipient: string
  sender: string
  subject: string
  purpose: string
  templateName?: string
  templateVariablesJson?: string
  userId?: string
  contextType?: string
  contextId?: string
  tenantId?: string
  sentAt: number
  errorCode: string
  errorMessage: string
}

export interface UpdateDeliveryStateInput {
  cloudflareMessageId: string
  deliveryState: 'delivered' | 'bounced' | 'rejected' | 'delivery_failed'
  errorMessage?: string
  syncedAt: number
}

export interface EmailLogFilterOpts {
  limit: number
  offset: number
  purpose?: string     // '' = all; exact match on `purpose` column
  status?: string      // '' = all; use STATUS_SQL mapping — NOT a direct WHERE bind
  timeRangeMs?: number // duration ms; service computes Date.now() - timeRangeMs internally
  search?: string      // '' = no filter; LIKE on recipient OR subject
  tenantId?: string    // always null today; load-bearing when multi-tenant ships
}

export interface EmailStats {
  last24hTotal: number
  last24hSubmitted: number  // status='submitted' AND delivery_state IS NULL
  last24hFailed: number     // status='failed_at_send'
  last24hDelivered: number  // status='submitted' AND delivery_state='delivered'
  lastTestedAt: number | null // MAX(sent_at) WHERE purpose='test' AND status='submitted'
}

// Pre-written safe SQL clause strings. opts.status is used only as a lookup
// key — it is NEVER interpolated into SQL. This prevents SQL injection on
// the two-column status model where naive `WHERE status = ?` binding would
// silently return wrong results for 'delivered', 'bounced', etc.
const STATUS_SQL: Record<string, string> = {
  submitted:        "status = 'submitted' AND delivery_state IS NULL",
  failed_at_send:   "status = 'failed_at_send'",
  delivered:        "status = 'submitted' AND delivery_state = 'delivered'",
  bounced:          "delivery_state = 'bounced'",
  rejected:         "delivery_state = 'rejected'",
  delivery_failed:  "delivery_state = 'delivery_failed'",
}

export class EmailLogService {
  constructor(private readonly db: D1Database) {}

  /**
   * Records a successful submission to CF Email Service. `status` =
   * `'submitted'`, `delivery_state` remains NULL until reconciliation runs.
   */
  async insertOnSubmit(input: InsertOnSubmitInput): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO email_log (
          id, cloudflare_message_id, recipient, sender, subject,
          purpose, template_name, template_variables_json,
          user_id, context_type, context_id, tenant_id,
          sent_at, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'submitted')`,
      )
      .bind(
        input.id,
        input.cloudflareMessageId,
        input.recipient,
        input.sender,
        input.subject,
        input.purpose,
        input.templateName ?? null,
        input.templateVariablesJson ?? null,
        input.userId ?? null,
        input.contextType ?? null,
        input.contextId ?? null,
        input.tenantId ?? null,
        input.sentAt,
      )
      .run()
  }

  /**
   * Records a `failed_at_send` row when the CF Email Service call itself
   * rejected. `cloudflare_message_id` is NULL on these rows (no message ID
   * was returned).
   */
  async insertOnFailedAtSend(input: InsertOnFailedAtSendInput): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO email_log (
          id, cloudflare_message_id, recipient, sender, subject,
          purpose, template_name, template_variables_json,
          user_id, context_type, context_id, tenant_id,
          sent_at, status, error_code, error_message
        ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'failed_at_send', ?, ?)`,
      )
      .bind(
        input.id,
        input.recipient,
        input.sender,
        input.subject,
        input.purpose,
        input.templateName ?? null,
        input.templateVariablesJson ?? null,
        input.userId ?? null,
        input.contextType ?? null,
        input.contextId ?? null,
        input.tenantId ?? null,
        input.sentAt,
        input.errorCode,
        input.errorMessage,
      )
      .run()
  }

  /**
   * Reconciliation cron writes. Matches by `cloudflare_message_id`, only
   * updates rows where `delivery_synced_at IS NULL` (idempotency + late-
   * bounce-signal capture per Q3 design doc Decision 4).
   */
  async updateDeliveryState(input: UpdateDeliveryStateInput): Promise<void> {
    await this.db
      .prepare(
        `UPDATE email_log SET
          delivery_state = ?,
          delivery_synced_at = ?,
          error_message = COALESCE(?, error_message)
        WHERE cloudflare_message_id = ? AND delivery_synced_at IS NULL`,
      )
      .bind(
        input.deliveryState,
        input.syncedAt,
        input.errorMessage ?? null,
        input.cloudflareMessageId,
      )
      .run()
  }

  /**
   * Loader for the admin observability UI's list view + per-message detail
   * view. Returns at most `limit` rows ordered by `sent_at DESC`. Tenant
   * filter optional (NULL today; load-bearing when multi-tenant ships).
   */
  async list(opts: { limit: number; tenantId?: string }): Promise<EmailLogRow[]> {
    /* v8 ignore next 4 -- tenantId branch: multi-tenant infrastructure, always null today */
    const stmt = opts.tenantId
      ? this.db
          .prepare(
            `SELECT * FROM email_log WHERE tenant_id = ? ORDER BY sent_at DESC LIMIT ?`,
          )
          .bind(opts.tenantId, opts.limit)
      : this.db
          .prepare(`SELECT * FROM email_log ORDER BY sent_at DESC LIMIT ?`)
          .bind(opts.limit)

    const result = await stmt.all<EmailLogRow>()
    return result.results ?? []
  }

  async listFiltered(opts: EmailLogFilterOpts): Promise<{ rows: EmailLogRow[]; total: number }> {
    const where: string[] = []
    const binds: (string | number | null)[] = []

    /* v8 ignore next 4 -- tenantId branch: multi-tenant infrastructure, always null today */
    if (opts.tenantId) {
      where.push('tenant_id = ?')
      binds.push(opts.tenantId)
    }

    if (opts.purpose) {
      where.push('purpose = ?')
      binds.push(opts.purpose)
    }

    if (opts.status) {
      const statusClause = STATUS_SQL[opts.status]
      if (statusClause) {
        // No bind parameter — STATUS_SQL values are static strings, not user input
        where.push(statusClause)
      }
    }

    if (opts.timeRangeMs) {
      where.push('sent_at >= ?')
      binds.push(Date.now() - opts.timeRangeMs)
    }

    if (opts.search) {
      where.push("(recipient LIKE '%' || ? || '%' OR subject LIKE '%' || ? || '%')")
      binds.push(opts.search, opts.search)
    }

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : ''

    const [rowsResult, countResult] = await Promise.all([
      this.db
        .prepare(
          `SELECT * FROM email_log ${whereClause} ORDER BY sent_at DESC LIMIT ? OFFSET ?`,
        )
        .bind(...binds, opts.limit, opts.offset)
        .all<EmailLogRow>(),
      this.db
        .prepare(`SELECT COUNT(*) as count FROM email_log ${whereClause}`)
        .bind(...binds)
        .first<{ count: number }>(),
    ])

    return {
      rows: rowsResult.results ?? [],
      total: countResult?.count ?? 0,
    }
  }

  async getStats(windowMs: number): Promise<EmailStats> {
    const threshold = Date.now() - windowMs

    interface StatsRow {
      total: number
      failed: number
      submitted: number
      delivered: number
    }

    interface LastTestedRow {
      last_tested: number | null
    }

    const [statsRow, lastTestedRow] = await Promise.all([
      this.db
        .prepare(
          `SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'failed_at_send' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'submitted' AND delivery_state IS NULL THEN 1 ELSE 0 END) as submitted,
            SUM(CASE WHEN status = 'submitted' AND delivery_state = 'delivered' THEN 1 ELSE 0 END) as delivered
          FROM email_log WHERE sent_at >= ?`,
        )
        .bind(threshold)
        .first<StatsRow>(),
      this.db
        .prepare(
          `SELECT MAX(sent_at) as last_tested FROM email_log WHERE purpose = 'test' AND status = 'submitted'`,
        )
        .first<LastTestedRow>(),
    ])

    return {
      last24hTotal:     statsRow?.total     ?? 0,
      last24hFailed:    statsRow?.failed    ?? 0,
      last24hSubmitted: statsRow?.submitted ?? 0,
      last24hDelivered: statsRow?.delivered ?? 0,
      lastTestedAt:     lastTestedRow?.last_tested ?? null,
    }
  }

  async getDistinctPurposes(): Promise<string[]> {
    const result = await this.db
      .prepare(`SELECT DISTINCT purpose FROM email_log ORDER BY purpose ASC`)
      .all<{ purpose: string }>()
    return (result.results ?? []).map(r => r.purpose)
  }
}
