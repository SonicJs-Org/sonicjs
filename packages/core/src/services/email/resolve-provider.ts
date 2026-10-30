/**
 * Email provider resolution
 *
 * Decides which transport an app uses, in precedence order:
 *
 *   1. an explicit `provider` instance  (dev brought their own — wins outright)
 *   2. an explicit `providerName` built-in, credentialed from env
 *   3. env auto-detect: RESEND_API_KEY → Resend, else SENDGRID_API_KEY → SendGrid
 *   4. the Console provider (zero-config dev/CI fallback)
 *
 * If a chosen provider turns out to be unconfigured (e.g. `providerName: 'resend'`
 * with no key), it falls back to Console with a warning rather than failing sends
 * silently — so a missing key degrades to "logged, not delivered", never to a
 * security leak (a reset flow returning its own token because mail didn't send).
 */

import type { EmailProvider } from './types'
import { ResendProvider } from './providers/resend'
import { SendGridProvider } from './providers/sendgrid'
import { ConsoleProvider } from './providers/console'

export type BuiltInProviderName = 'resend' | 'sendgrid' | 'console'

export interface ResolveEmailProviderOptions {
  /** A ready-made provider — highest precedence (this is "use whatever you want"). */
  provider?: EmailProvider
  /** Force a specific built-in by name. */
  providerName?: BuiltInProviderName
  /** Worker env / process env bag (read for RESEND_API_KEY / SENDGRID_API_KEY). */
  env?: Record<string, unknown>
  /** Injected fetch for the built-ins (tests). */
  fetchImpl?: typeof fetch
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function buildNamed(
  name: BuiltInProviderName,
  env: Record<string, unknown>,
  fetchImpl?: typeof fetch
): EmailProvider {
  switch (name) {
    case 'resend':
      return new ResendProvider({ apiKey: str(env.RESEND_API_KEY), fetchImpl })
    case 'sendgrid':
      return new SendGridProvider({ apiKey: str(env.SENDGRID_API_KEY), fetchImpl })
    case 'console':
      return new ConsoleProvider()
  }
}

/** Resolve the email provider to use. Always returns a usable provider. */
export function resolveEmailProvider(options: ResolveEmailProviderOptions = {}): EmailProvider {
  const env = options.env ?? {}

  // 1. Explicit instance wins.
  if (options.provider) return options.provider

  // 2/3. Named built-in, or env auto-detect.
  let provider: EmailProvider
  if (options.providerName) {
    provider = buildNamed(options.providerName, env, options.fetchImpl)
  } else if (str(env.RESEND_API_KEY)) {
    provider = new ResendProvider({ apiKey: str(env.RESEND_API_KEY), fetchImpl: options.fetchImpl })
  } else if (str(env.SENDGRID_API_KEY)) {
    provider = new SendGridProvider({ apiKey: str(env.SENDGRID_API_KEY), fetchImpl: options.fetchImpl })
  } else {
    provider = new ConsoleProvider()
  }

  // 4. Never ship an unconfigured provider — degrade to Console, loudly.
  if (!provider.isConfigured()) {
    // eslint-disable-next-line no-console
    console.warn(
      `[email] provider "${provider.name}" is not configured (missing API key); ` +
        `falling back to the console provider — emails will be logged, not delivered.`
    )
    return new ConsoleProvider()
  }

  return provider
}
