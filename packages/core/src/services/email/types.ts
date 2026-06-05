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
export interface EmailProvider {
  /** Stable identifier recorded in `email_log.provider` (e.g. `'resend'`). */
  readonly name: string
  /** True if the provider has everything it needs to send (credentials, etc.). */
  isConfigured(): boolean
  /** Attempt delivery. Must not throw for ordinary failures — return `ok: false`. */
  send(message: NormalizedEmailMessage): Promise<SendResult>
}
