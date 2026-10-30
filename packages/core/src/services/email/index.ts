/**
 * Provider-agnostic email service — public surface.
 *
 * Use whatever provider you want: pass a built-in name, let env auto-detect, or
 * supply your own `EmailProvider`. Every send is recorded in `email_log`.
 */

export type {
  EmailMessage,
  NormalizedEmailMessage,
  SendResult,
  EmailProvider,
} from './types'

export { EmailService } from './email-service'
export type { EmailServiceOptions, EmailLogDb } from './email-service'

export { ResendProvider } from './providers/resend'
export type { ResendProviderOptions } from './providers/resend'
export { SendGridProvider } from './providers/sendgrid'
export type { SendGridProviderOptions } from './providers/sendgrid'
export { ConsoleProvider } from './providers/console'
export type { ConsoleProviderOptions } from './providers/console'

export { resolveEmailProvider } from './resolve-provider'
export type { ResolveEmailProviderOptions, BuiltInProviderName } from './resolve-provider'

export { loadDbEmailSettings, dbSettingsFrom } from './db-settings'
export type { DbEmailSettings } from './db-settings'

export {
  getEmailService,
  setEmailService,
  hasEmailService,
  resetEmailService,
} from './email-service-singleton'
