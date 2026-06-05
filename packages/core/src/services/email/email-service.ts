/**
 * EmailService — the single send chokepoint
 *
 * Every email in the app goes through `EmailService.send()`:
 *  1. normalize the message (resolve `from`, coerce recipients to arrays),
 *  2. hand it to the configured {@link EmailProvider},
 *  3. record the attempt in `email_log` (status, provider, provider id, error).
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
  /** When provided, every send writes a row to `email_log`. */
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

  /** Best-effort insert into `email_log`. Returns the row id, or undefined if not logged. */
  private async writeLog(message: NormalizedEmailMessage, result: SendResult): Promise<string | undefined> {
    if (!this.db) return undefined
    const id = this.idFactory()
    const ts = this.now()
    try {
      await this.db
        .prepare(
          `INSERT INTO email_log (
             id, to_email, from_email, subject, status, provider, provider_id,
             error, flow, metadata, failed_at_send, delivery_state, delivery_synced_at, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          id,
          message.to.join(','),
          message.from,
          message.subject,
          result.ok ? 'sent' : 'failed',
          result.provider,
          result.providerId ?? null,
          result.error ?? null,
          message.flow ?? null,
          message.metadata ? JSON.stringify(message.metadata) : null,
          result.ok ? null : ts,
          null,
          null,
          ts
        )
        .run()
      return id
    } catch (error) {
      // Logging must never break a send.
      // eslint-disable-next-line no-console
      console.error('[email] failed to write email_log row:', error)
      return undefined
    }
  }
}
