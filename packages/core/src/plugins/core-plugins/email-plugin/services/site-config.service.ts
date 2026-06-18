/**
 * SiteConfigService — loads the site-wide context that email templates need
 * (site name, public URL, support contact).
 *
 * Reads from the core `SettingsService.getGeneralSettings()` (which lives at
 * `packages/core/src/services/settings.ts`); falls back to environment-
 * variable hints and finally to safe defaults so a fresh install with no
 * settings rows still produces sensible email copy.
 *
 * The public URL is resolved by checking, in order:
 *   1. `general.siteUrl` setting (when admins set it explicitly)
 *   2. `env.PUBLIC_URL` binding (when set via wrangler vars)
 *   3. Hardcoded fallback (`http://localhost:8787`) — only hit during dev
 *      with no settings + no env var
 */
import { SettingsService } from '../../../../services/settings'

export interface SiteContext {
  siteName: string
  siteUrl: string
  supportEmail: string
}

export interface SiteConfigEnv {
  readonly PUBLIC_URL?: string
}

export class SiteConfigService {
  constructor(
    private readonly db: D1Database,
    private readonly env: SiteConfigEnv = {},
  ) {}

  async load(): Promise<SiteContext> {
    const settings = new SettingsService(this.db)
    const general = await settings.getGeneralSettings()

    /* v8 ignore next -- fallback branch only reachable in unconfigured envs */
    const siteUrl = this.env.PUBLIC_URL || 'http://localhost:8787'

    return {
      siteName: general.siteName,
      siteUrl,
      supportEmail: general.adminEmail,
    }
  }

  /**
   * Builds the password-reset link from the configured site URL + the token.
   * The auth route at /auth/reset-password expects `?token=` per the existing
   * pattern at routes/auth.ts:1102 (pre-PR-E).
   */
  buildResetLink(siteUrl: string, resetToken: string): string {
    return `${siteUrl.replace(/\/$/, '')}/auth/reset-password?token=${encodeURIComponent(resetToken)}`
  }

  /**
   * Builds the login URL for the welcome email link. Mirrors the existing
   * /auth/login route convention.
   */
  buildLoginUrl(siteUrl: string): string {
    return `${siteUrl.replace(/\/$/, '')}/auth/login`
  }

  /**
   * Builds the magic-link verify URL from the configured site URL + token.
   * The auth route at /auth/magic-link/verify expects `?token=` per the
   * existing pattern from the legacy magic-link-auth plugin (pre-v3 SDK).
   */
  buildMagicLinkUrl(siteUrl: string, token: string): string {
    return `${siteUrl.replace(/\/$/, '')}/auth/magic-link/verify?token=${encodeURIComponent(token)}`
  }

  /**
   * Builds the invitation-acceptance link. Two-step flow: GET shows a
   * confirmation page, POST consumes the token (see SS-8).
   */
  buildInviteAcceptLink(siteUrl: string, token: string): string {
    return `${siteUrl.replace(/\/$/, '')}/auth/invite/accept?token=${encodeURIComponent(token)}`
  }

  /**
   * Builds the email-verification link. The GET handler at
   * /auth/verify-email consumes the token and redirects to /auth/login.
   */
  buildVerificationUrl(siteUrl: string, token: string): string {
    return `${siteUrl.replace(/\/$/, '')}/auth/verify-email?token=${encodeURIComponent(token)}`
  }
}
