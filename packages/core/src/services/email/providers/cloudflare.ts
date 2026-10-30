/**
 * Cloudflare Email binding provider (MailChannels / send_email binding)
 *
 * Sends email through a Cloudflare `send_email` Workers binding.
 * Configure via `wrangler.toml`:
 *
 *   [[send_email]]
 *   name = "SEND_EMAIL"
 *   destination_address = "you@yourdomain.com"  # optional allowlist
 *
 * Then pass `SEND_EMAIL` as the `binding` when constructing:
 *   new CloudflareEmailProvider({ binding: env.SEND_EMAIL, defaultFrom: 'no-reply@example.com' })
 *
 * Note: delivery state tracking is not available through the MailChannels API;
 * the `reconcile()` method is a no-op for this provider. Production delivery
 * monitoring should use Cloudflare Email Event Notifications (separate webhook).
 */

import type { EmailProvider, NormalizedEmailMessage, SendResult } from '../types'

/** Minimal shape of the Cloudflare `send_email` binding object. */
export interface CFSendEmailBinding {
  /** Send an RFC-2822 formatted email. */
  send(message: { from: string; to: string[]; subject: string; html?: string; text?: string; reply_to?: string }): Promise<void>
}

export interface CloudflareEmailProviderOptions {
  /** The `send_email` binding from `env`. */
  binding: CFSendEmailBinding
  /** Default from-address (must be verified on your Cloudflare account). */
  defaultFrom?: string
}

export class CloudflareEmailProvider implements EmailProvider {
  readonly name = 'cloudflare-email'
  private readonly binding: CFSendEmailBinding
  private readonly defaultFrom: string

  constructor(options: CloudflareEmailProviderOptions) {
    this.binding = options.binding
    this.defaultFrom = options.defaultFrom ?? 'noreply@sonicjs.local'
  }

  isConfigured(): boolean {
    return !!this.binding && typeof this.binding.send === 'function'
  }

  async send(message: NormalizedEmailMessage): Promise<SendResult> {
    try {
      await this.binding.send({
        from: message.from || this.defaultFrom,
        to: message.to,
        subject: message.subject,
        ...(message.html ? { html: message.html } : {}),
        ...(message.text ? { text: message.text } : {}),
        ...(message.replyTo ? { reply_to: message.replyTo } : {}),
      })
      return { ok: true, provider: this.name }
    } catch (err) {
      return {
        ok: false,
        provider: this.name,
        error: err instanceof Error ? err.message : String(err),
      }
    }
  }

  // reconcile() is a no-op: MailChannels doesn't expose a delivery-status API.
  // Use Cloudflare Email Routing event notifications for delivery monitoring.
}
