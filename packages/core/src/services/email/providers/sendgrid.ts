/**
 * SendGrid email provider
 *
 * https://docs.sendgrid.com/api-reference/mail-send/mail-send
 */

import type { EmailProvider, NormalizedEmailMessage, SendResult } from '../types'

const SENDGRID_ENDPOINT = 'https://api.sendgrid.com/v3/mail/send'

export interface SendGridProviderOptions {
  apiKey?: string
  endpoint?: string
  fetchImpl?: typeof fetch
}

export class SendGridProvider implements EmailProvider {
  readonly name = 'sendgrid'
  private readonly apiKey?: string
  private readonly endpoint: string
  private readonly fetchImpl: typeof fetch

  constructor(options: SendGridProviderOptions = {}) {
    this.apiKey = options.apiKey
    this.endpoint = options.endpoint ?? SENDGRID_ENDPOINT
    this.fetchImpl = options.fetchImpl ?? fetch
  }

  isConfigured(): boolean {
    return !!this.apiKey
  }

  async send(message: NormalizedEmailMessage): Promise<SendResult> {
    if (!this.isConfigured()) {
      return { ok: false, provider: this.name, error: 'SendGrid API key is not configured' }
    }
    try {
      const content: Array<{ type: string; value: string }> = []
      if (message.text) content.push({ type: 'text/plain', value: message.text })
      if (message.html) content.push({ type: 'text/html', value: message.html })

      const res = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          personalizations: [
            {
              to: message.to.map((email) => ({ email })),
              cc: message.cc?.map((email) => ({ email })),
              bcc: message.bcc?.map((email) => ({ email })),
            },
          ],
          from: { email: message.from },
          reply_to: message.replyTo ? { email: message.replyTo } : undefined,
          subject: message.subject,
          content,
          headers: message.headers,
        }),
      })

      if (!res.ok) {
        const detail = await safeText(res)
        return { ok: false, provider: this.name, error: `SendGrid responded ${res.status}: ${detail}` }
      }

      // SendGrid returns 202 with an empty body; the message id is in a header.
      const providerId = res.headers.get('x-message-id') ?? undefined
      return { ok: true, provider: this.name, providerId }
    } catch (error) {
      return { ok: false, provider: this.name, error: error instanceof Error ? error.message : String(error) }
    }
  }
}

async function safeText(res: Response): Promise<string> {
  try {
    return (await res.text()).slice(0, 500)
  } catch {
    return '<unreadable body>'
  }
}
