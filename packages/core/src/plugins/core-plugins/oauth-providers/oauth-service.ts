/**
 * OAuth Service
 * Handles OAuth2 authorization code flow, token exchange, and user info fetching.
 * Provider-agnostic — each provider is a simple config object.
 */

import type { D1Database } from '@cloudflare/workers-types'

// ─── Provider Configuration ─────────────────────────────────────────────────

export interface OAuthProviderConfig {
  id: string
  name: string
  authorizeUrl: string
  tokenUrl: string
  userInfoUrl: string
  scopes: string[]
  /** Map provider profile JSON to a normalized user profile */
  mapProfile: (profile: Record<string, any>) => OAuthUserProfile
}

export interface OAuthUserProfile {
  providerAccountId: string
  email: string
  name: string
  avatar?: string
}

export interface OAuthPluginSettings {
  providers: Record<string, {
    clientId: string
    clientSecret: string
    enabled: boolean
  }>
}

// ─── Built-in Providers ─────────────────────────────────────────────────────

export const GITHUB_PROVIDER: OAuthProviderConfig = {
  id: 'github',
  name: 'GitHub',
  authorizeUrl: 'https://github.com/login/oauth/authorize',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  userInfoUrl: 'https://api.github.com/user',
  scopes: ['read:user', 'user:email'],
  mapProfile: (profile) => ({
    providerAccountId: String(profile.id),
    email: profile.email || '',
    name: profile.name || profile.login || '',
    avatar: profile.avatar_url || undefined
  })
}

export const GOOGLE_PROVIDER: OAuthProviderConfig = {
  id: 'google',
  name: 'Google',
  authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
  scopes: ['openid', 'email', 'profile'],
  mapProfile: (profile) => ({
    providerAccountId: String(profile.id),
    email: profile.email || '',
    name: profile.name || '',
    avatar: profile.picture || undefined
  })
}

export const BUILT_IN_PROVIDERS: Record<string, OAuthProviderConfig> = {
  github: GITHUB_PROVIDER,
  google: GOOGLE_PROVIDER
}

// ─── OAuth Account DB Record ────────────────────────────────────────────────

export interface OAuthAccount {
  id: string
  user_id: string
  provider: string
  provider_account_id: string
  access_token: string | null
  refresh_token: string | null
  token_expires_at: number | null
  profile_data: string | null
  created_at: number
  updated_at: number
}

// ─── OAuth Service ──────────────────────────────────────────────────────────

export class OAuthService {
  constructor(private db: D1Database) {}

  /**
   * Build the authorization redirect URL for a provider.
   */
  buildAuthorizeUrl(
    provider: OAuthProviderConfig,
    clientId: string,
    redirectUri: string,
    state: string
  ): string {
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: provider.scopes.join(' '),
      state
    })

    // Google requires access_type for refresh tokens
    if (provider.id === 'google') {
      params.set('access_type', 'offline')
      params.set('prompt', 'consent')
    }

    return `${provider.authorizeUrl}?${params.toString()}`
  }

  /**
   * Exchange authorization code for tokens using native fetch.
   */
  async exchangeCode(
    provider: OAuthProviderConfig,
    clientId: string,
    clientSecret: string,
    code: string,
    redirectUri: string
  ): Promise<{ access_token: string; refresh_token?: string; expires_in?: number }> {
    const body: Record<string, string> = {
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    }

    const response = await fetch(provider.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: new URLSearchParams(body).toString()
    })

    if (!response.ok) {
      const errorText = await response.text()
      throw new Error(`Token exchange failed (${response.status}): ${errorText}`)
    }

    const data = await response.json() as Record<string, any>

    if (data.error) {
      throw new Error(`Token exchange error: ${data.error_description || data.error}`)
    }

    return {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in ? Number(data.expires_in) : undefined
    }
  }

  /**
   * Fetch user profile from the provider's userinfo endpoint.
   */
  async fetchUserProfile(
    provider: OAuthProviderConfig,
    accessToken: string
  ): Promise<OAuthUserProfile> {
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/json'
    }

    // GitHub uses a different auth header format
    if (provider.id === 'github') {
      headers['Authorization'] = `token ${accessToken}`
    }

    const response = await fetch(provider.userInfoUrl, { headers })

    if (!response.ok) {
      throw new Error(`Failed to fetch user profile (${response.status})`)
    }

    const profile = await response.json() as Record<string, any>

    // For GitHub, email may not be in the profile — fetch from /user/emails
    if (provider.id === 'github' && !profile.email) {
      const emailResponse = await fetch('https://api.github.com/user/emails', {
        headers: {
          'Authorization': `token ${accessToken}`,
          'Accept': 'application/json'
        }
      })

      if (emailResponse.ok) {
        const emails = await emailResponse.json() as Array<{ email: string; primary: boolean; verified: boolean }>
        const primaryEmail = emails.find(e => e.primary && e.verified)
        if (primaryEmail) {
          profile.email = primaryEmail.email
        }
      }
    }

    return provider.mapProfile(profile)
  }

  // ─── Database Operations ────────────────────────────────────────────────

  /**
   * Find an existing OAuth account link.
   */
  async findOAuthAccount(
    provider: string,
    providerAccountId: string
  ): Promise<OAuthAccount | null> {
    return await this.db.prepare(`
      SELECT * FROM oauth_accounts
      WHERE provider = ? AND provider_account_id = ?
    `).bind(provider, providerAccountId).first() as OAuthAccount | null
  }

  /**
   * Find all OAuth accounts for a user.
   */
  async findUserOAuthAccounts(userId: string): Promise<OAuthAccount[]> {
    const result = await this.db.prepare(`
      SELECT * FROM oauth_accounts WHERE user_id = ?
    `).bind(userId).all()
    return (result.results || []) as unknown as OAuthAccount[]
  }

  /**
   * Create a new OAuth account link.
   */
  async createOAuthAccount(params: {
    userId: string
    provider: string
    providerAccountId: string
    accessToken: string
    refreshToken?: string
    tokenExpiresAt?: number
    profileData?: string
  }): Promise<OAuthAccount> {
    const id = crypto.randomUUID()
    const now = Date.now()

    await this.db.prepare(`
      INSERT INTO oauth_accounts (
        id, user_id, provider, provider_account_id,
        access_token, refresh_token, token_expires_at,
        profile_data, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      params.userId,
      params.provider,
      params.providerAccountId,
      params.accessToken,
      params.refreshToken || null,
      params.tokenExpiresAt || null,
      params.profileData || null,
      now,
      now
    ).run()

    return {
      id,
      user_id: params.userId,
      provider: params.provider,
      provider_account_id: params.providerAccountId,
      access_token: params.accessToken,
      refresh_token: params.refreshToken || null,
      token_expires_at: params.tokenExpiresAt || null,
      profile_data: params.profileData || null,
      created_at: now,
      updated_at: now
    }
  }

  /**
   * Update tokens for an existing OAuth account.
   */
  async updateOAuthTokens(
    id: string,
    accessToken: string,
    refreshToken?: string,
    tokenExpiresAt?: number
  ): Promise<void> {
    await this.db.prepare(`
      UPDATE oauth_accounts
      SET access_token = ?, refresh_token = ?, token_expires_at = ?, updated_at = ?
      WHERE id = ?
    `).bind(accessToken, refreshToken || null, tokenExpiresAt || null, Date.now(), id).run()
  }

  /**
   * Unlink an OAuth account from a user (only if they have another auth method).
   */
  async unlinkOAuthAccount(userId: string, provider: string): Promise<boolean> {
    // Check user has a password or another OAuth link before unlinking
    const user = await this.db.prepare(`
      SELECT password_hash FROM users WHERE id = ?
    `).bind(userId).first() as { password_hash: string | null } | null

    const otherLinks = await this.db.prepare(`
      SELECT COUNT(*) as count FROM oauth_accounts
      WHERE user_id = ? AND provider != ?
    `).bind(userId, provider).first() as { count: number } | null

    const hasPassword = !!user?.password_hash
    const hasOtherLinks = (otherLinks?.count || 0) > 0

    if (!hasPassword && !hasOtherLinks) {
      return false // Cannot unlink the only auth method
    }

    await this.db.prepare(`
      DELETE FROM oauth_accounts WHERE user_id = ? AND provider = ?
    `).bind(userId, provider).run()

    return true
  }

  /**
   * Find a user by email.
   */
  async findUserByEmail(email: string): Promise<{
    id: string
    email: string
    role: string
    is_active: number
    first_name: string
    last_name: string
  } | null> {
    return await this.db.prepare(`
      SELECT id, email, role, is_active, first_name, last_name
      FROM users WHERE email = ?
    `).bind(email.toLowerCase()).first() as any
  }

  /**
   * Create a new user from an OAuth profile.
   */
  async createUserFromOAuth(profile: OAuthUserProfile): Promise<string> {
    const id = crypto.randomUUID()
    const now = Date.now()
    const email = profile.email.toLowerCase()
    const nameParts = (profile.name || email.split('@')[0] || 'User').split(' ')
    const firstName = nameParts[0] || 'User'
    const lastName = nameParts.slice(1).join(' ') || ''
    const username = email.split('@')[0] || id.substring(0, 8)

    // Check for username collision and append random suffix if needed
    const existing = await this.db.prepare(
      'SELECT id FROM users WHERE username = ?'
    ).bind(username).first()

    const finalUsername = existing
      ? `${username}-${id.substring(0, 6)}`
      : username

    await this.db.prepare(`
      INSERT INTO users (
        id, email, username, first_name, last_name,
        password_hash, role, avatar, is_active, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, NULL, 'viewer', ?, 1, ?, ?)
    `).bind(
      id, email, finalUsername, firstName, lastName,
      profile.avatar || null, now, now
    ).run()

    return id
  }

  /**
   * Generate a cryptographically random state parameter for CSRF protection.
   */
  generateState(): string {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
  }
}
