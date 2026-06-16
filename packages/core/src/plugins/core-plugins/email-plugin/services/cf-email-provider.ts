/**
 * CloudflareEmailProvider — wraps the CF Email Workers binding (`env.EMAIL`)
 * into the core `EmailProvider` interface so it can be registered with the
 * core `EmailService` singleton (same path as Resend / SendGrid).
 *
 * The CF Email binding auth is via the `send_email` Workers binding — no API
 * key needed. `isConfigured()` returns true when the binding is present.
 */
import type { EmailProvider, NormalizedEmailMessage, SendResult } from '../../../../services/email/types'

interface CfEmailBinding {
  send(message: {
    from: string
    to: string | string[]
    subject: string
    html?: string
    text?: string
    cc?: string | string[]
    bcc?: string | string[]
    replyTo?: string
  }): Promise<{ messageId?: string }>
}

export class CloudflareEmailProvider implements EmailProvider {
  readonly name = 'cloudflare'

  constructor(private readonly binding: CfEmailBinding) {}

  isConfigured(): boolean {
    return !!this.binding
  }

  async send(message: NormalizedEmailMessage): Promise<SendResult> {
    try {
      const result = await this.binding.send({
        from: message.from,
        to: (message.to.length === 1 ? message.to[0] : message.to) as string | string[],
        subject: message.subject,
        ...(message.html !== undefined ? { html: message.html } : {}),
        ...(message.text !== undefined ? { text: message.text } : {}),
        ...(message.cc !== undefined ? { cc: message.cc as string | string[] } : {}),
        ...(message.bcc !== undefined ? { bcc: message.bcc as string | string[] } : {}),
        ...(message.replyTo !== undefined ? { replyTo: message.replyTo } : {}),
      })
      return {
        ok: true,
        provider: this.name,
        providerId: result?.messageId,
      }
    } catch (err) {
      return {
        ok: false,
        provider: this.name,
        error: err instanceof Error ? err.message : String(err),
      }
    }
  }
}
