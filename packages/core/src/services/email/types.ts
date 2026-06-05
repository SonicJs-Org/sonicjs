/**
 * Provider-agnostic email types
 *
 * The whole point of this layer: a SonicJS app sends mail through one
 * `EmailService` chokepoint, and the *transport* is a swappable `EmailProvider`.
 * Built-ins ship for Resend and SendGrid, but a developer can drop in any
 * implementation of `EmailProvider` (Postmark, SES, an internal relay, a mock in
 * tests) without touching call sites. Every send is recorded in `email_log`.
 */

/** A message as authored by a caller. `from` is optional (the service fills a default). */
export interface EmailMessage {
  to: string | string[]
  subject: string
  html?: string
  text?: string
  /** Overrides the service's default from-address. */
  from?: string
  replyTo?: string
  cc?: string | string[]
  bcc?: string | string[]
  /** Extra transport headers. */
  headers?: Record<string, string>
  /**
   * Logical flow this send belongs to (e.g. `'password-reset'`, `'otp'`,
   * `'magic-link'`, `'welcome'`, `'test'`). Recorded in `email_log.flow` for
   * observability; does not affect delivery.
   */
  flow?: string
  /** Free-form metadata recorded (as JSON) in `email_log.metadata`. */
  metadata?: Record<string, unknown>
}

/** A message after the service has resolved defaults — what a provider receives. */
export interface NormalizedEmailMessage extends Omit<EmailMessage, 'to' | 'cc' | 'bcc'> {
  to: string[]
  from: string
  cc?: string[]
  bcc?: string[]
}

/** Outcome of a single send attempt. */
export interface SendResult {
  ok: boolean
  /** Provider that handled (or attempted) the send. */
  provider: string
  /** Provider-side message id, when the transport returns one. */
  providerId?: string
  /** Error message when `ok` is false. */
  error?: string
  /** id of the `email_log` row written for this attempt, when logging is enabled. */
  logId?: string
}

/**
 * A swappable email transport.
 *
 * Implement this to support any provider. `isConfigured()` lets the service (and
 * `resolveEmailProvider`) decide whether a provider is usable before attempting a
 * send — e.g. a Resend provider with no API key reports `false`.
 */
/**
 * A row from `email_log` as seen by the reconciliation method.
 * Contains the fields a provider needs to check delivery status.
 */
export interface EmailLogRow {
  id: string
  provider_id?: string | null
  provider: string
  status: 'sent' | 'failed' | string
  delivery_state?: string | null
}

export interface EmailProvider {
  /** Stable identifier recorded in `email_log.provider` (e.g. `'resend'`). */
  readonly name: string
  /** True if the provider has everything it needs to send (credentials, etc.). */
  isConfigured(): boolean
  /** Attempt delivery. Must not throw for ordinary failures — return `ok: false`. */
  send(message: NormalizedEmailMessage): Promise<SendResult>
  /**
   * Optional: reconcile delivery state for a batch of recently-sent messages.
   *
   * Called by the core `email-reconciliation` cron. Providers that expose a
   * delivery/event API (e.g. Cloudflare Email with delivery webhooks) implement
   * this to backfill `delivery_state`. Providers without delivery status APIs
   * (e.g. Resend, SendGrid at the current integration level) leave this undefined
   * — those rows stay with `delivery_state = null`.
   *
   * Returning an array of `{ id, delivery_state }` updates the matching rows in
   * `email_log`. Errors do not propagate (cron is fire-and-log).
   */
  reconcile?(rows: EmailLogRow[]): Promise<Array<{ id: string; delivery_state: string }>>
}
