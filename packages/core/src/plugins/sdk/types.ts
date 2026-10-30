export type { TypedHookHandler as SonicHookHandler } from '../hooks/typed-hooks'

/**
 * CF Email Service-specific types for the email-plugin's EmailServiceImpl.
 * Portability types from mmcintosh/sonicjs-infowall-merge.
 */
export interface SendEmailOptions {
  to: string
  subject: string
  html?: string
  text?: string
  from?: string
  fromName?: string
  replyTo?: string
  cc?: string | string[]
  bcc?: string | string[]
  /** Logical flow (e.g. 'welcome', 'password_reset', 'test'). Required by EmailServiceImpl. */
  purpose: string
  userId?: string
  templateName?: string
  templateVariables?: Record<string, unknown>
  contextType?: string
  contextId?: string
  tenantId?: string
}

export interface SendEmailResult {
  status: 'submitted' | 'failed_at_send'
  cloudflareMessageId?: string
  logId?: string
  errorCode?: string
  errorMessage?: string
}

export interface EmailService {
  send(options: SendEmailOptions): Promise<SendEmailResult>
}
