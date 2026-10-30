/**
 * EmailServiceImpl — the v3 email-plugin's `EmailService` implementation.
 *
 * Validates `SendEmailOptions`, resolves `from` against D1 settings when the
 * caller omitted it, builds the Cloudflare Email Service plain-object
 * payload, calls `env.EMAIL.send(...)`, writes an `email_log` row for the
 * outcome, and returns `SendEmailResult`.
 *
 * Per Decision 6 (LOCKED) validation rules:
 *   1. At least one of `html` / `text` REQUIRED (throws `EmailValidationError`)
 *   2. Email address shape validation on `to`, `from`, all `cc` / `bcc`
 *      (RFC-5322-lite — `local@domain.tld` shape, not full RFC validation)
 *   3. `purpose` REQUIRED and non-empty (matches migration 106
 *      `purpose TEXT NOT NULL`)
 *   4. `from` resolution: `SendEmailOptions.from || settings.fromEmail`;
 *      if both absent, throws `EmailValidationError`
 *
 * Error semantics (hybrid throw/data):
 *   - Validation errors throw `EmailValidationError` (caller error; Hono
 *     `app.onError` maps to 400)
 *   - Transport-side outcomes return `SendEmailResult` (caller decides
 *     retry vs. log vs. surface)
 *
 * Per Decision 7 (LOCKED), settings are read on every send — no caching
 * in the first iteration.
 */
import type {
  EmailService,
  SendEmailOptions,
  SendEmailResult,
} from '../../../sdk/types'
import { EmailValidationError } from '../errors'
import { EmailLogService } from './email-log.service'
import { EmailSettingsService } from './settings.service'

// RFC-5322-lite address regex — `local@domain.tld`. Strict enough to catch
// common typos; not a full RFC validator (those exist but introduce more
// edge cases than they prevent in practice).
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

function validateAddress(field: string, value: string): void {
  if (!EMAIL_REGEX.test(value)) {
    throw new EmailValidationError(field, `'${value}' is not a valid email address`)
  }
}

function validateAddressList(field: string, value: string | string[] | undefined): void {
  if (value === undefined) return
  const list = Array.isArray(value) ? value : [value]
  for (const addr of list) {
    validateAddress(field, addr)
  }
}

function randomId(): string {
  return crypto.randomUUID()
}

export class EmailServiceImpl implements EmailService {
  private readonly settings: EmailSettingsService
  private readonly log: EmailLogService

  constructor(
    private readonly binding: SendEmail,
    private readonly db: D1Database,
  ) {
    this.settings = new EmailSettingsService(db)
    this.log = new EmailLogService(db)
  }

  async send(options: SendEmailOptions): Promise<SendEmailResult> {
    // 1. Validate shape (purpose + at least one of html/text)
    if (!options.purpose || options.purpose.trim() === '') {
      throw new EmailValidationError('purpose', 'purpose is required and must be non-empty')
    }
    if (!options.html && !options.text) {
      throw new EmailValidationError('body', 'at least one of `html` or `text` is required')
    }

    // 2. Validate addresses
    validateAddress('to', options.to)
    validateAddressList('cc', options.cc)
    validateAddressList('bcc', options.bcc)

    // 3. Resolve `from` (caller-supplied OR settings.fromEmail)
    const settings = await this.settings.load()
    const from = options.from ?? settings.fromEmail
    if (!from) {
      throw new EmailValidationError(
        'from',
        'from address must be supplied on the send call OR configured as `fromEmail` in plugin settings',
      )
    }
    validateAddress('from', from)

    const replyTo = options.replyTo ?? settings.replyTo

    // 4. Build CF Email Service payload (plain-object form per smoke-test
    //    2026-04-30; workers-types `SendEmail.send` second overload).
    const payload: Parameters<SendEmail['send']>[0] = {
      from,
      to: options.to,
      subject: options.subject,
      ...(options.html !== undefined ? { html: options.html } : {}),
      ...(options.text !== undefined ? { text: options.text } : {}),
      ...(options.cc !== undefined ? { cc: options.cc } : {}),
      ...(options.bcc !== undefined ? { bcc: options.bcc } : {}),
      ...(replyTo !== undefined ? { replyTo } : {}),
    }

    const sentAt = Date.now()
    const logId = randomId()
    const templateVariablesJson = options.templateVariables
      ? JSON.stringify(options.templateVariables)
      : undefined

    // 5. Send + log
    try {
      const result = await this.binding.send(payload)
      const cloudflareMessageId = result.messageId

      await this.log.insertOnSubmit({
        id: logId,
        cloudflareMessageId,
        recipient: options.to,
        sender: from,
        subject: options.subject,
        purpose: options.purpose,
        templateName: options.templateName,
        templateVariablesJson,
        userId: options.userId,
        contextType: options.contextType,
        contextId: options.contextId,
        tenantId: options.tenantId,
        sentAt,
      })

      return {
        status: 'submitted',
        cloudflareMessageId,
        logId,
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      const errorCode = err instanceof Error && 'code' in err && typeof err.code === 'string'
        ? err.code
        : 'CF_EMAIL_SEND_FAILED'

      console.error('[email-service] binding.send() failed', { to: options.to, purpose: options.purpose, errorCode, errorMessage })

      // Log the failure but don't let log-write failures mask the original
      // transport error. If log-write itself fails, surface a clear error
      // — the caller's view is "transport failed" either way.
      try {
        await this.log.insertOnFailedAtSend({
          id: logId,
          recipient: options.to,
          sender: from,
          subject: options.subject,
          purpose: options.purpose,
          templateName: options.templateName,
          templateVariablesJson,
          userId: options.userId,
          contextType: options.contextType,
          contextId: options.contextId,
          tenantId: options.tenantId,
          sentAt,
          errorCode,
          errorMessage,
        })
      } catch (logErr) {
        /* v8 ignore next 4 -- double-failure: send failed + log write failed */
        console.error('[email-plugin] failed to write failed_at_send log row', {
          originalError: errorMessage,
          logError: logErr instanceof Error ? logErr.message : String(logErr),
        })
      }

      return {
        status: 'failed_at_send',
        logId,
        errorCode,
        errorMessage,
      }
    }
  }
}
