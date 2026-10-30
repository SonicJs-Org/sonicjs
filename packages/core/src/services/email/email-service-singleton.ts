/**
 * EmailService singleton
 *
 * Env-independent access to the app's EmailService. Cron / `scheduled()` handlers
 * (delivery reconciliation) and any code outside the request context reach the
 * service through here, mirroring the hook-system singleton. The app factory sets
 * it at construction; call sites read it via `getEmailService()`.
 */

import { createServiceSingleton } from '../../plugins/singletons/service-singleton'
import type { EmailService } from './email-service'

const singleton = createServiceSingleton<EmailService>('EmailService')

/** Set the process-wide EmailService. Last write wins. */
export function setEmailService(service: EmailService): void {
  singleton.set(service)
}

/**
 * Get the process-wide EmailService.
 * @throws if no EmailService has been set yet.
 */
export function getEmailService(): EmailService {
  return singleton.get()
}

/** True if an EmailService has been set. */
export function hasEmailService(): boolean {
  return singleton.has()
}

/** Clear the singleton (test isolation). */
export function resetEmailService(): void {
  singleton.reset()
}
