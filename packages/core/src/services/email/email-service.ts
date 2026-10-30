/**
 * EmailService — the single send chokepoint
 *
 * Every email in the app goes through `EmailService.send()`:
 *  1. normalize the message (resolve `from`, coerce recipients to arrays),
 *  2. hand it to the configured {@link EmailProvider},
 *  3. record the attempt as an `email_log` document in the `documents` table
 *     (type_id='email_log', single draft version, never published).
 *
 * Logging is best-effort: a logging failure never fails the send. Providers must
 * not throw for ordinary delivery failures (they return `ok: false`), so the
 * service surfaces a structured {@link SendResult} rather than exceptions.
 */

import type { EmailMessage, EmailProvider, NormalizedEmailMessage, SendResult } from './types'

/**
 * Minimal structural D1 surface needed for logging. Avoids importing the full
 * `D1Database` type and keeps the service trivially fakeable in tests.
 */
export interface EmailLogDb {
  prepare(query: string): {
    bind(...values: unknown[]): { run(): Promise<unknown> }
  }
}

export interface EmailServiceOptions {
  /** The transport. */
  provider: EmailProvider
  /** Default from-address used when a message omits `from`. */
  defaultFrom: string
  /** Default reply-to applied when a message omits `replyTo`. */
  defaultReplyTo?: string
  /** When provided, every send writes an email_log document to the documents table. */
  db?: EmailLogDb
  /** Injectable clock (tests). Defaults to `Date.now`. */
  now?: () => number
  /** Injectable id factory (tests). Defaults to `crypto.randomUUID`. */
  idFactory?: () => string
}

function toArray(value: string | string[] | undefined): string[] | undefined {
  if (value === undefined) return undefined
  return Array.isArray(value) ? value : [value]
}

export class EmailService {
  private readonly provider: EmailProvider
  private readonly defaultFrom: string
  private readonly defaultReplyTo?: string
  private readonly db?: EmailLogDb
  private readonly now: () => number
  private readonly idFactory: () => string

  constructor(options: EmailServiceOptions) {
    this.provider = options.provider
    this.defaultFrom = options.defaultFrom
    this.defaultReplyTo = options.defaultReplyTo
    this.db = options.db
    this.now = options.now ?? (() => Date.now())
    this.idFactory = options.idFactory ?? (() => crypto.randomUUID())
  }

  /** Name of the active transport (e.g. `'resend'`). */
  getProviderName(): string {
    return this.provider.name
  }

  /** True if the active transport is ready to send. */
  isConfigured(): boolean {
    return this.provider.isConfigured()
  }

  /**
   * Ask the active provider to reconcile delivery state for a batch of
   * recently-sent email_log document rows. Returns empty array when the provider
   * does not implement `reconcile()` (Resend, SendGrid, Console).
   *
   * Called by the `email-reconciliation` cron plugin.
   */
  async reconcileDelivery(
    rows: import('./types').EmailLogRow[]
  ): Promise<Array<{ id: string; delivery_state: string }>> {
    if (!this.provider.reconcile) return []
    try {
      return await this.provider.reconcile(rows)
    } catch (err) {
      console.error('[email] reconcile() failed:', err)
      return []
    }
  }

  /** Normalize, send, and log. Never throws for ordinary delivery failures. */
  async send(message: EmailMessage): Promise<SendResult> {
    const normalized: NormalizedEmailMessage = {
      ...message,
      to: toArray(message.to) ?? [],
      from: message.from ?? this.defaultFrom,
      replyTo: message.replyTo ?? this.defaultReplyTo,
      cc: toArray(message.cc),
      bcc: toArray(message.bcc),
    }

    let result: SendResult
    try {
      result = await this.provider.send(normalized)
    } catch (error) {
      // A misbehaving provider that throws is still surfaced as a structured failure.
      result = {
        ok: false,
        provider: this.provider.name,
        error: error instanceof Error ? error.message : String(error),
      }
    }

    const logId = await this.writeLog(normalized, result)
    return logId ? { ...result, logId } : result
  }

  /**
   * Best-effort write of an email_log document into the `documents` table.
   * Documents use SECONDS for timestamps (not ms). Email log entries are
   * draft-only (is_current_draft=1, is_published=0, maxVersionsPerRoot=1).
   * Returns the new document's root_id, or undefined if logging is disabled / fails.
   */
  private async writeLog(message: NormalizedEmailMessage, result: SendResult): Promise<string | undefined> {
    if (!this.db) return undefined
    const rootId = this.idFactory()
    const docId = this.idFactory()
    // Documents table uses SECONDS (D29)
    const tsSeconds = Math.floor(this.now() / 1000)

    const data = JSON.stringify({
      toEmail: message.to.join(','),
      fromEmail: message.from,
      subject: message.subject,
      status: result.ok ? 'sent' : 'failed',
      provider: result.provider,
      providerId: result.providerId ?? null,
      error: result.error ?? null,
      flow: message.flow ?? null,
      metadata: message.metadata ?? null,
      failedAtSend: result.ok ? null : tsSeconds,
      deliveryState: null,
      deliverySyncedAt: null,
    })

    try {
      await this.db
        .prepare(
          `INSERT INTO documents (
             id, root_id, type_id, type_version, version_number,
             is_current_draft, is_published, status,
             parent_root_id, tenant_id, locale, translation_group_id,
             title, data, metadata, sort_order, visible,
             created_at, updated_at
           ) VALUES (
             ?, ?, 'email_log', 1, 1,
             1, 0, 'draft',
             '', 'default', 'default', '',
             ?, ?, '{}', 0, 1,
             ?, ?
           )`
        )
        .bind(
          docId,
          rootId,
          message.subject ?? '',
          data,
          tsSeconds,
          tsSeconds
        )
        .run()
      return rootId
    } catch (error) {
      // Logging must never break a send.
      // eslint-disable-next-line no-console
      console.error('[email] failed to write email_log document:', error)
      return undefined
    }
  }
}
