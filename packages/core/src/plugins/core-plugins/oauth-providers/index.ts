/**
 * OAuth Providers Plugin
 *
 * OAuth2/OIDC social login support for SonicJS.
 * Phase 1: Core OAuth2 authorization code flow with GitHub and Google providers.
 *
 * Routes:
 *   GET  /auth/oauth/:provider          → Redirect to provider authorization
 *   GET  /auth/oauth/:provider/callback → Handle OAuth callback
 *   POST /auth/oauth/link               → Link OAuth provider to logged-in account
 *   POST /auth/oauth/unlink             → Unlink OAuth provider from account
 *   GET  /auth/oauth/accounts           → List linked OAuth accounts for current user
 */

import { Hono } from 'hono'
import { setCookie, getCookie } from 'hono/cookie'
import { PluginBuilder } from '../../sdk/plugin-builder'
import type { Plugin } from '@sonicjs-cms/core'
import {
  OAuthService,
  BUILT_IN_PROVIDERS,
  type OAuthPluginSettings,
  type OAuthProviderConfig
} from './oauth-service'
import { AuthManager } from '../../../middleware'

const STATE_COOKIE_NAME = 'oauth_state'
const STATE_COOKIE_MAX_AGE = 600 // 10 minutes

export function createOAuthProvidersPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: 'oauth-providers',
    version: '1.0.0-beta.1',
    description: 'OAuth2/OIDC social login with GitHub, Google, and more'
  })

  builder.metadata({
    author: {
      name: 'SonicJS Team',
      email: 'team@sonicjs.com'
    },
    license: 'MIT',
    compatibility: '^2.0.0'
  })

  // ==================== Helper Functions ====================

  function getCallbackUrl(c: any, provider: string): string {
    const proto = c.req.header('x-forwarded-proto') || 'https'
    const host = c.req.header('host') || 'localhost'
    return `${proto}://${host}/auth/oauth/${provider}/callback`
  }

  async function loadSettings(db: any): Promise<OAuthPluginSettings | null> {
    const row = await db.prepare(
      `SELECT settings FROM plugins WHERE id = 'oauth-providers'`
    ).first() as { settings: string | null } | null

    if (!row?.settings) return null

    try {
      return JSON.parse(row.settings) as OAuthPluginSettings
    } catch {
      return null
    }
  }

  function getProviderCredentials(
    settings: OAuthPluginSettings | null,
    providerId: string
  ): { clientId: string; clientSecret: string } | null {
    if (!settings?.providers?.[providerId]) return null
    const p = settings.providers[providerId]
    if (!p.enabled || !p.clientId || !p.clientSecret) return null
    return { clientId: p.clientId, clientSecret: p.clientSecret }
  }

  // ==================== API Routes ====================

  const oauthAPI = new Hono()

  // GET /auth/oauth/:provider — Redirect to provider authorization
  oauthAPI.get('/:provider', async (c: any) => {
    try {
      const providerId = c.req.param('provider')
      const providerConfig = BUILT_IN_PROVIDERS[providerId]

      if (!providerConfig) {
        return c.json({ error: `Unknown OAuth provider: ${providerId}` }, 400)
      }

      const db = c.env.DB
      const settings = await loadSettings(db)
      const creds = getProviderCredentials(settings, providerId)

      if (!creds) {
        return c.json({
          error: `OAuth provider "${providerId}" is not configured or not enabled`
        }, 400)
      }

      const oauthService = new OAuthService(db)
      const state = oauthService.generateState()
      const redirectUri = getCallbackUrl(c, providerId)

      // Store state in a cookie for CSRF validation on callback
      setCookie(c, STATE_COOKIE_NAME, state, {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax', // Lax required for OAuth redirect flow
        maxAge: STATE_COOKIE_MAX_AGE,
        path: '/auth/oauth'
      })

      const authorizeUrl = oauthService.buildAuthorizeUrl(
        providerConfig,
        creds.clientId,
        redirectUri,
        state
      )

      return c.redirect(authorizeUrl)
    } catch (error) {
      console.error('OAuth authorize error:', error)
      return c.json({ error: 'Failed to initiate OAuth flow' }, 500)
    }
  })

  // GET /auth/oauth/:provider/callback — Handle OAuth callback
  oauthAPI.get('/:provider/callback', async (c: any) => {
    try {
      const providerId = c.req.param('provider')
      const providerConfig = BUILT_IN_PROVIDERS[providerId]

      if (!providerConfig) {
        return c.redirect('/auth/login?error=Unknown OAuth provider')
      }

      // Validate state (CSRF protection)
      const stateParam = c.req.query('state')
      const stateCookie = getCookie(c, STATE_COOKIE_NAME)

      if (!stateParam || !stateCookie || stateParam !== stateCookie) {
        return c.redirect('/auth/login?error=Invalid OAuth state. Please try again.')
      }

      // Clear the state cookie
      setCookie(c, STATE_COOKIE_NAME, '', {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
        maxAge: 0,
        path: '/auth/oauth'
      })

      // Check for error from provider
      const errorParam = c.req.query('error')
      if (errorParam) {
        const errorDesc = c.req.query('error_description') || errorParam
        return c.redirect(`/auth/login?error=${encodeURIComponent(errorDesc)}`)
      }

      const code = c.req.query('code')
      if (!code) {
        return c.redirect('/auth/login?error=No authorization code received')
      }

      const db = c.env.DB
      const settings = await loadSettings(db)
      const creds = getProviderCredentials(settings, providerId)

      if (!creds) {
        return c.redirect('/auth/login?error=OAuth provider not configured')
      }

      const oauthService = new OAuthService(db)
      const redirectUri = getCallbackUrl(c, providerId)

      // Exchange code for tokens
      const tokens = await oauthService.exchangeCode(
        providerConfig,
        creds.clientId,
        creds.clientSecret,
        code,
        redirectUri
      )

      // Fetch user profile from provider
      const profile = await oauthService.fetchUserProfile(providerConfig, tokens.access_token)

      if (!profile.email) {
        return c.redirect('/auth/login?error=Could not retrieve email from OAuth provider. Please ensure your email is public or grant email permission.')
      }

      const tokenExpiresAt = tokens.expires_in
        ? Date.now() + (tokens.expires_in * 1000)
        : null

      // Check if this OAuth account is already linked to a user
      const existingOAuth = await oauthService.findOAuthAccount(providerId, profile.providerAccountId)

      if (existingOAuth) {
        // Existing OAuth link — update tokens and log in
        await oauthService.updateOAuthTokens(
          existingOAuth.id,
          tokens.access_token,
          tokens.refresh_token,
          tokenExpiresAt ?? undefined
        )

        // Fetch user to generate JWT
        const user = await db.prepare(
          'SELECT id, email, role, is_active FROM users WHERE id = ?'
        ).bind(existingOAuth.user_id).first() as any

        if (!user || !user.is_active) {
          return c.redirect('/auth/login?error=Account is deactivated')
        }

        const jwt = await AuthManager.generateToken(
          user.id, user.email, user.role,
          (c.env as any).JWT_SECRET
        )

        AuthManager.setAuthCookie(c, jwt, { sameSite: 'Lax' })
        return c.redirect('/admin')
      }

      // No existing OAuth link — check if user exists by email
      const existingUser = await oauthService.findUserByEmail(profile.email)

      if (existingUser) {
        if (!existingUser.is_active) {
          return c.redirect('/auth/login?error=Account is deactivated')
        }

        // Link OAuth to existing account
        await oauthService.createOAuthAccount({
          userId: existingUser.id,
          provider: providerId,
          providerAccountId: profile.providerAccountId,
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
          tokenExpiresAt: tokenExpiresAt ?? undefined,
          profileData: JSON.stringify(profile)
        })

        const jwt = await AuthManager.generateToken(
          existingUser.id, existingUser.email, existingUser.role,
          (c.env as any).JWT_SECRET
        )

        AuthManager.setAuthCookie(c, jwt, { sameSite: 'Lax' })
        return c.redirect('/admin')
      }

      // Brand new user — create account from OAuth profile
      const newUserId = await oauthService.createUserFromOAuth(profile)

      await oauthService.createOAuthAccount({
        userId: newUserId,
        provider: providerId,
        providerAccountId: profile.providerAccountId,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        tokenExpiresAt: tokenExpiresAt ?? undefined,
        profileData: JSON.stringify(profile)
      })

      const jwt = await AuthManager.generateToken(
        newUserId, profile.email.toLowerCase(), 'viewer',
        (c.env as any).JWT_SECRET
      )

      AuthManager.setAuthCookie(c, jwt, { sameSite: 'Lax' })
      return c.redirect('/admin')

    } catch (error) {
      console.error('OAuth callback error:', error)
      const message = error instanceof Error ? error.message : 'OAuth authentication failed'
      return c.redirect(`/auth/login?error=${encodeURIComponent(message)}`)
    }
  })

  // POST /auth/oauth/link — Link an OAuth provider to the current logged-in user
  oauthAPI.post('/link', async (c: any) => {
    try {
      const user = c.get('user')
      if (!user) {
        return c.json({ error: 'Authentication required' }, 401)
      }

      const body = await c.req.json()
      const { provider } = body

      if (!provider || !BUILT_IN_PROVIDERS[provider]) {
        return c.json({ error: 'Invalid provider' }, 400)
      }

      // Redirect the user to the OAuth flow — the callback will auto-link
      // since the user already exists by email
      const db = c.env.DB
      const settings = await loadSettings(db)
      const creds = getProviderCredentials(settings, provider)

      if (!creds) {
        return c.json({ error: `OAuth provider "${provider}" is not configured` }, 400)
      }

      const oauthService = new OAuthService(db)
      const state = oauthService.generateState()
      const redirectUri = getCallbackUrl(c, provider)

      setCookie(c, STATE_COOKIE_NAME, state, {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
        maxAge: STATE_COOKIE_MAX_AGE,
        path: '/auth/oauth'
      })

      const authorizeUrl = oauthService.buildAuthorizeUrl(
        BUILT_IN_PROVIDERS[provider]!,
        creds.clientId,
        redirectUri,
        state
      )

      return c.json({ redirectUrl: authorizeUrl })
    } catch (error) {
      console.error('OAuth link error:', error)
      return c.json({ error: 'Failed to initiate account linking' }, 500)
    }
  })

  // POST /auth/oauth/unlink — Unlink an OAuth provider from the current user
  oauthAPI.post('/unlink', async (c: any) => {
    try {
      const user = c.get('user')
      if (!user) {
        return c.json({ error: 'Authentication required' }, 401)
      }

      const body = await c.req.json()
      const { provider } = body

      if (!provider) {
        return c.json({ error: 'Provider is required' }, 400)
      }

      const db = c.env.DB
      const oauthService = new OAuthService(db)
      const success = await oauthService.unlinkOAuthAccount(user.userId, provider)

      if (!success) {
        return c.json({
          error: 'Cannot unlink the only authentication method. Set a password first.'
        }, 400)
      }

      return c.json({ success: true, message: `${provider} account unlinked` })
    } catch (error) {
      console.error('OAuth unlink error:', error)
      return c.json({ error: 'Failed to unlink account' }, 500)
    }
  })

  // GET /auth/oauth/accounts — List linked OAuth accounts for current user
  oauthAPI.get('/accounts', async (c: any) => {
    try {
      const user = c.get('user')
      if (!user) {
        return c.json({ error: 'Authentication required' }, 401)
      }

      const db = c.env.DB
      const oauthService = new OAuthService(db)
      const accounts = await oauthService.findUserOAuthAccounts(user.userId)

      return c.json({
        accounts: accounts.map(a => ({
          provider: a.provider,
          providerAccountId: a.provider_account_id,
          linkedAt: a.created_at
        }))
      })
    } catch (error) {
      console.error('OAuth accounts error:', error)
      return c.json({ error: 'Failed to fetch linked accounts' }, 500)
    }
  })

  // Register routes
  builder.addRoute('/auth/oauth', oauthAPI, {
    description: 'OAuth2 social login endpoints',
    requiresAuth: false,
    priority: 100
  })

  // Add menu item for admin settings
  builder.addMenuItem('OAuth Providers', '/admin/plugins/oauth-providers', {
    icon: 'shield',
    order: 86,
    permissions: ['oauth:manage']
  })

  // Lifecycle hooks
  builder.lifecycle({
    activate: async () => {
      console.info('✅ OAuth Providers plugin activated')
    },
    deactivate: async () => {
      console.info('❌ OAuth Providers plugin deactivated')
    }
  })

  return builder.build() as Plugin
}

export const oauthProvidersPlugin = createOAuthProvidersPlugin()
