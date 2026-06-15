/**
 * Plugin-internal types for the v3 email-plugin (PR-E Phase B, 2026-05-13).
 *
 * Public types (`EmailService`, `SendEmailOptions`, `SendEmailResult`) live
 * in `packages/core/src/plugins/sdk/types.ts` — those are part of the v3 SDK
 * contract and consumed across plugin/host boundaries. The types here are
 * private to email-plugin services + handlers.
 */

/**
 * Shape of the JSON stored in `plugins.settings` for plugin id `'email'`.
 * Loaded on every send via `settings.service.ts` (Decision 7 — no caching
 * in the first iteration; ~1ms parse per send is acceptable).
 *
 * Fields:
 *   - `fromEmail` / `fromName` — required for sending. If absent and the
 *     caller didn't supply `from` on `SendEmailOptions`, `EmailServiceImpl`
 *     throws `EmailValidationError`.
 *   - `replyTo` — optional. Sent as the `reply_to` field on the CF Email
 *     Service request when set.
 *   - `logoUrl` — optional. Used by template helpers (rendered into the
 *     email HTML body); not part of the SMTP envelope.
 *
 * Legacy `apiKey` field (Resend era) is intentionally absent — Cloudflare
 * Email Service auth is via the bound `EMAIL` send_email binding, not a
 * settings-stored API key. The admin settings UI no longer accepts apiKey;
 * existing rows with apiKey survive in D1 but are ignored.
 */
export interface EmailSettings {
  fromEmail?: string
  fromName?: string
  replyTo?: string
  logoUrl?: string
  /** CF Account ID for the reconciliation cron. Env CF_ACCOUNT_ID takes priority. */
  cfAccountId?: string
  /** CF API token (Email Routing read). Env EMAIL_API_TOKEN takes priority. */
  cfEmailApiToken?: string
}

/**
 * Row shape returned by D1 reads against `email_log`. Mirrors migration 106's
 * schema (see `packages/core/migrations/106_email_log.sql`). All Cloudflare-
 * synced fields are nullable (`delivery_state`, `delivery_synced_at`,
 * `cloudflare_message_id` on failed_at_send rows).
 */
export interface EmailLogRow {
  id: string
  cloudflare_message_id: string | null
  recipient: string
  sender: string
  subject: string
  purpose: string
  template_name: string | null
  template_variables_json: string | null
  user_id: string | null
  context_type: string | null
  context_id: string | null
  tenant_id: string | null
  sent_at: number
  status: 'submitted' | 'failed_at_send'
  error_code: string | null
  error_message: string | null
  delivery_state: 'delivered' | 'bounced' | 'rejected' | 'delivery_failed' | null
  delivery_synced_at: number | null
}

/**
 * Single row from the Cloudflare GraphQL Activity Log query
 * (`emailSendingAdaptive` dataset). Used by `reconciliation.ts` to update
 * `email_log.delivery_state` + `delivery_synced_at` for matching rows.
 *
 * The `status` field maps directly to `email_log.delivery_state` via
 * `mapGraphQLStatusToDeliveryState` (in `reconciliation.ts`). `errorCause`
 * is captured into `email_log.error_message` when the delivery_state
 * indicates failure (`bounced` / `delivery_failed`).
 *
 * Shape derived from hub spec §6.3 + §8 (`messageId`, `status`,
 * `errorCause`).
 */
export interface GraphQLActivityLogRow {
  messageId: string
  status: 'delivered' | 'deliveryFailed' | 'bounced' | 'rejected'
  errorCause?: string
  datetime?: string
}
