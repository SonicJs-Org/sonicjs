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
 *
 * `provider` selects the transport. Env vars always win over DB values:
 *   - `RESEND_API_KEY` env → forces Resend regardless of `provider` field
 *   - `EMAIL` CF binding present → enables Cloudflare Email Service option
 *   - `CF_ACCOUNT_ID` / `EMAIL_API_TOKEN` env → override reconciliation creds
 */
export interface EmailSettings {
  /** Which email transport to use. Defaults to 'cloudflare' when EMAIL binding is present, else 'resend'. */
  provider?: 'resend' | 'cloudflare'
  /** Resend API key. Env RESEND_API_KEY takes priority. */
  resendApiKey?: string
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
