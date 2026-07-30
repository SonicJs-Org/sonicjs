/**
 * OTP Login Plugin
 *
 * Passwordless authentication via email one-time codes
 * Users receive a secure 6-digit code to sign in without passwords
 */

import { Hono } from 'hono'
import { setCookie } from 'hono/cookie'
import { z } from 'zod'
import { definePlugin } from '../../sdk/define-plugin'
import type { DefinedPlugin } from '../../sdk/define-plugin'
import { OTPService, type OTPSettings } from './otp-service'
import { renderOTPEmail } from './email-templates'
import { AuthManager } from '../../../middleware'
import { getEmailService, hasEmailService } from '../../../services/email/email-service-singleton'
import { getJwtExpirySecondsFromDb } from '../../../middleware/auth'
import { hasVerifiedSecondFactor } from '../../../auth/second-factor-guard'
import { SettingsService } from '../../../services/settings'
import { getCustomData } from '../user-profiles'
import { dispatchHookEvent } from '../../hooks/dispatch-event'

// Validation schemas
const otpRequestSchema = z.object({
  email: z.string().email('Valid email is required')
})

const otpVerifySchema = z.object({
  email: z.string().email('Valid email is required'),
  code: z.string().min(4).max(8)
})

// Default settings (site name comes from general settings)
const DEFAULT_SETTINGS: OTPSettings = {
  codeLength: 6,
  codeExpiryMinutes: 10,
  maxAttempts: 3,
  rateLimitPerHour: 5,
  allowNewUserRegistration: false,
  logoUrl: '',
  logoWidth: 150,
  logoBorderWidth: 0,
  logoBorderColor: '#ffffff',
  loginUrl: '',
  loginButtonText: ''
}

function buildOtpApi(): Hono {
  const otpAPI = new Hono()

  // POST /auth/otp/request - Request OTP code
  otpAPI.post('/request', async (c: any) => {
    try {
      const body = await c.req.json()
      const validation = otpRequestSchema.safeParse(body)

      if (!validation.success) {
        return c.json({
          error: 'Validation failed',
          details: validation.error.issues
        }, 400)
      }

      const { email } = validation.data
      const normalizedEmail = email.toLowerCase()
      const db = c.env.DB
      const otpService = new OTPService(db)

      // Load plugin settings from database
      let settings: OTPSettings = { ...DEFAULT_SETTINGS }
      const pluginRow = await db.prepare(`
        SELECT settings FROM plugins WHERE id = 'otp-login'
      `).first() as { settings: string | null } | null
      if (pluginRow?.settings) {
        try {
          const savedSettings = JSON.parse(pluginRow.settings)
          settings = { ...DEFAULT_SETTINGS, ...savedSettings }
        } catch (e) {
          console.warn('Failed to parse OTP plugin settings, using defaults')
        }
      }

      // Get site name from general settings
      const settingsService = new SettingsService(db)
      const generalSettings = await settingsService.getGeneralSettings()
      const siteName = generalSettings.siteName

      // Check rate limiting
      const canRequest = await otpService.checkRateLimit(normalizedEmail, settings)
      if (!canRequest) {
        return c.json({
          error: 'Too many requests. Please try again in an hour.'
        }, 429)
      }

      // Check if user exists
      const user = await db.prepare(`
        SELECT id, email, role, is_active
        FROM auth_user
        WHERE email = ?
      `).bind(normalizedEmail).first() as any

      if (!user && !settings.allowNewUserRegistration) {
        // Don't reveal if user exists or not (security)
        return c.json({
          message: 'If an account exists for this email, you will receive a verification code shortly.',
          expiresIn: settings.codeExpiryMinutes * 60
        })
      }

      if (user && !user.is_active) {
        return c.json({
          error: 'This account has been deactivated.'
        }, 403)
      }

      // Get IP and user agent
      const ipAddress = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown'
      const userAgent = c.req.header('user-agent') || 'unknown'

      // Create OTP code
      const otpCode = await otpService.createOTPCode(
        normalizedEmail,
        settings,
        ipAddress,
        userAgent
      )

      // Send email via Email plugin
      try {
        const isDevMode = c.env.ENVIRONMENT === 'development'

        if (isDevMode) {
          console.log(`[DEV] OTP Code for ${normalizedEmail}: ${otpCode.code}`)
        }

        // Prepare email content
        const emailContent = renderOTPEmail({
          code: otpCode.code,
          expiryMinutes: settings.codeExpiryMinutes,
          codeLength: settings.codeLength,
          maxAttempts: settings.maxAttempts,
          email: normalizedEmail,
          ipAddress,
          timestamp: new Date().toISOString(),
          appName: siteName,
          logoUrl: settings.logoUrl || '',
          logoWidth: settings.logoWidth,
          logoBorderWidth: settings.logoBorderWidth,
          logoBorderColor: settings.logoBorderColor || '',
          loginUrl: settings.loginUrl || '',
          loginButtonText: settings.loginButtonText || ''
        })

        // Send via the shared, provider-agnostic EmailService. This stays
        // synchronous (caller-direct): the user can't proceed without the code,
        // so a fire-and-forget send would silently fail them. The send is logged
        // to email_log like every other flow. (Previously this read plugins.settings
        // and called Resend directly; the EmailService now owns provider selection,
        // including honoring those same admin-UI settings.)
        if (hasEmailService()) {
          const sent = await getEmailService().send({
            to: normalizedEmail,
            subject: `Your login code for ${siteName}`,
            flow: 'otp',
            html: emailContent.html,
            text: emailContent.text,
          })
          if (!sent.ok) {
            // Don't expose delivery errors to the user for security - just log it.
            console.error('Failed to send OTP email:', sent.error)
          }
        } else {
          console.warn('EmailService not initialized; OTP email not sent')
        }

        const response: any = {
          message: 'If an account exists for this email, you will receive a verification code shortly.',
          expiresIn: settings.codeExpiryMinutes * 60
        }

        // In development, include the code
        if (isDevMode) {
          response.dev_code = otpCode.code
        }

        return c.json(response)
      } catch (emailError) {
        console.error('Error sending OTP email:', emailError)
        return c.json({
          error: 'Failed to send verification code. Please try again.'
        }, 500)
      }
    } catch (error) {
      console.error('OTP request error:', error)
      return c.json({
        error: 'An error occurred. Please try again.'
      }, 500)
    }
  })

  // POST /auth/otp/verify - Verify OTP code
  otpAPI.post('/verify', async (c: any) => {
    try {
      const body = await c.req.json()
      const validation = otpVerifySchema.safeParse(body)

      if (!validation.success) {
        return c.json({
          error: 'Validation failed',
          details: validation.error.issues
        }, 400)
      }

      const { email, code } = validation.data
      const normalizedEmail = email.toLowerCase()
      const db = c.env.DB
      const otpService = new OTPService(db)

      // Load plugin settings from database
      let settings = { ...DEFAULT_SETTINGS }
      const pluginRow = await db.prepare(`
        SELECT settings FROM plugins WHERE id = 'otp-login'
      `).first() as { settings: string | null } | null
      if (pluginRow?.settings) {
        try {
          const savedSettings = JSON.parse(pluginRow.settings)
          settings = { ...DEFAULT_SETTINGS, ...savedSettings }
        } catch (e) {
          console.warn('Failed to parse OTP plugin settings, using defaults')
        }
      }

      // Verify the code
      const verification = await otpService.verifyCode(normalizedEmail, code, settings)

      if (!verification.valid) {
        // Increment attempts on failure
        await otpService.incrementAttempts(normalizedEmail, code)

        return c.json({
          error: verification.error || 'Invalid code',
          attemptsRemaining: verification.attemptsRemaining
        }, 401)
      }

      // Code is valid - get user
      let user = await db.prepare(`
        SELECT id, email, first_name, last_name, role, is_active, created_at
        FROM auth_user
        WHERE email = ?
      `).bind(normalizedEmail).first() as any

      if (!user && settings.allowNewUserRegistration) {
        // Auto-create new user on first OTP verification
        const userId = crypto.randomUUID()
        const now = Date.now()

        await db.prepare(`
          INSERT INTO auth_user (
            id, email, first_name, last_name,
            password_hash, role, is_active, email_verified, created_at, updated_at
          ) VALUES (?, ?, '', '', NULL, 'viewer', 1, 1, ?, ?)
        `).bind(userId, normalizedEmail, now, now).run()

        user = {
          id: userId,
          email: normalizedEmail,
          first_name: '',
          last_name: '',
          role: 'viewer',
          is_active: 1,
          created_at: now,
        }
      }

      if (!user) {
        return c.json({
          error: 'User not found'
        }, 404)
      }

      if (!user.is_active) {
        return c.json({
          error: 'Account is deactivated'
        }, 403)
      }

      // Second-factor gate. This route mints a session WITHOUT Better Auth, so BA's second-factor
      // challenge never runs here — which would leave an emailed code as a complete bypass of a
      // second factor the user deliberately enrolled in, while /admin/profile still read
      // "Enabled". It also sits ahead of the /auth/* catch-all in app.ts, so
      // guardPasswordlessSecondFactor never sees it; the check has to be here.
      //
      // Deliberately placed AFTER the code has been consumed, so a refused attempt also spends
      // the code — otherwise this becomes an oracle for probing which accounts have 2FA.
      if (await hasVerifiedSecondFactor(db, user.id)) {
        return c.json({
          error: 'This account uses two-factor authentication. Sign in with your password, then enter your authenticator code.'
        }, 403)
      }

      // Generate JWT token
      const tokenTtl = await getJwtExpirySecondsFromDb(db, c.env as any)
      const token = await AuthManager.generateToken(user.id, user.email, user.role, (c.env as any).JWT_SECRET, tokenTtl)

      // Set HTTP-only cookie
      setCookie(c, 'auth_token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: tokenTtl
      })

      // Fire auth:otp:verified for audit/analytics plugins (fire-and-forget).
      dispatchHookEvent(
        c,
        'auth:otp:verified',
        { user: { id: user.id, email: user.email, role: user.role } },
        'fire-and-forget'
      )

      const customData = await getCustomData(db, user.id)
      const { is_active: _isActive, ...publicUser } = user

      return c.json({
        success: true,
        user: {
          ...publicUser,
          ...customData,
        },
        token,
        message: 'Authentication successful'
      })
    } catch (error) {
      console.error('OTP verify error:', error)
      return c.json({
        error: 'An error occurred. Please try again.'
      }, 500)
    }
  })

  // POST /auth/otp/resend - Resend OTP code
  otpAPI.post('/resend', async (c: any) => {
    try {
      const body = await c.req.json()
      const validation = otpRequestSchema.safeParse(body)

      if (!validation.success) {
        return c.json({
          error: 'Validation failed',
          details: validation.error.issues
        }, 400)
      }

      // Reuse the request endpoint logic
      return otpAPI.fetch(
        new Request(c.req.url.replace('/resend', '/request'), {
          method: 'POST',
          headers: c.req.raw.headers,
          body: JSON.stringify({ email: validation.data.email })
        }),
        c.env
      )
    } catch (error) {
      console.error('OTP resend error:', error)
      return c.json({
        error: 'An error occurred. Please try again.'
      }, 500)
    }
  })

  return otpAPI
}

export const otpLoginPlugin: DefinedPlugin = definePlugin({
  id: 'otp-login',
  version: '1.0.0',
  name: 'OTP Login',
  description: 'Passwordless authentication via email one-time codes.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },
  capabilities: ['email:send'],

  register(app) {
    app.route('/auth/otp', buildOtpApi())
  },

  menu: [
    { label: 'OTP Login', path: '/admin/plugins/otp-login', icon: 'lock', order: 85, permissions: ['otp:manage'] },
  ],

  activate: async () => console.info('✅ OTP Login plugin activated'),
  deactivate: async () => console.info('❌ OTP Login plugin deactivated'),
})

export function createOTPLoginPlugin() {
  return otpLoginPlugin
}
