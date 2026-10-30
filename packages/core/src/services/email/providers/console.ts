/**
 * Console email provider
 *
 * The zero-config development fallback: instead of delivering, it logs the
 * message and reports success. This keeps local/dev and CI flows working without
 * real credentials, and — crucially — gives every send *somewhere* to go so that
 * flows like password reset never silently leak a token to the API caller just
 * because no provider was configured.
 *
 * It is `isConfigured()` === true by design (it always "works"), so it is the
 * safe terminal fallback in `resolveEmailProvider`.
 */

import type { EmailProvider, NormalizedEmailMessage, SendResult } from '../types'

export interface ConsoleProviderOptions {
  /** Sink for the rendered message. Defaults to `console.log`. */
  log?: (line: string) => void
  /** Include the HTML/text body in the log. Default false (subject + recipients only). */
  includeBody?: boolean
}

export class ConsoleProvider implements EmailProvider {
  readonly name = 'console'
  private readonly log: (line: string) => void
  private readonly includeBody: boolean

  constructor(options: ConsoleProviderOptions = {}) {
    // eslint-disable-next-line no-console
    this.log = options.log ?? ((line) => console.log(line))
    this.includeBody = options.includeBody ?? false
  }

  isConfigured(): boolean {
    return true
  }

  async send(message: NormalizedEmailMessage): Promise<SendResult> {
    const parts = [
      `[email:console] ${message.flow ? `(${message.flow}) ` : ''}`,
      `from=${message.from} to=${message.to.join(',')} subject=${JSON.stringify(message.subject)}`,
    ]
    if (this.includeBody && (message.text || message.html)) {
      parts.push(`\n${message.text ?? message.html}`)
    }
    this.log(parts.join(''))
    return { ok: true, provider: this.name, providerId: `console-${message.to.join(',')}` }
  }
}
