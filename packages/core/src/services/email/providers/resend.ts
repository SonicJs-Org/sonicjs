/**
 * Resend email provider
 *
 * https://resend.com/docs/api-reference/emails/send-email
 */

import type { EmailProvider, NormalizedEmailMessage, SendResult } from '../types'

const RESEND_ENDPOINT = 'https://api.resend.com/emails'

export interface ResendProviderOptions {
  apiKey?: string
  /** Override the API endpoint (tests). */
  endpoint?: string
  /** Injected fetch (tests / non-global environments). */
  fetchImpl?: typeof fetch
}

export class ResendProvider implements EmailProvider {
  readonly name = 'resend'
  private readonly apiKey?: string
  private readonly endpoint: string
  private readonly fetchImpl: typeof fetch

  constructor(options: ResendProviderOptions = {}) {
    this.apiKey = options.apiKey
    this.endpoint = options.endpoint ?? RESEND_ENDPOINT
    this.fetchImpl = options.fetchImpl ?? fetch
  }

  isConfigured(): boolean {
    return !!this.apiKey
  }

  async send(message: NormalizedEmailMessage): Promise<SendResult> {
    if (!this.isConfigured()) {
      return { ok: false, provider: this.name, error: 'Resend API key is not configured' }
    }
    try {
      const res = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: message.from,
          to: message.to,
          subject: message.subject,
          html: message.html,
          text: message.text,
          cc: message.cc,
          bcc: message.bcc,
          reply_to: message.replyTo,
          headers: message.headers,
        }),
      })

      if (!res.ok) {
        const detail = await safeText(res)
        return { ok: false, provider: this.name, error: `Resend responded ${res.status}: ${detail}` }
      }

      const body = (await res.json().catch(() => ({}))) as { id?: string }
      return { ok: true, provider: this.name, providerId: body.id }
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
