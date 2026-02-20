/**
 * OTP Login Plugin
 *
 * Passwordless authentication via email one-time codes
 * Users receive a secure 6-digit code to sign in without passwords
 */

import { Hono } from 'hono'
import { setCookie } from 'hono/cookie'
import { z } from 'zod'
import { PluginBuilder } from '../../sdk/plugin-builder'
import type { Plugin } from '@sonicjs-cms/core'
import { OTPService, type OTPSettings } from './otp-service'
import { renderOTPEmail } from './email-templates'
import { AuthManager } from '../../../middleware'
import { SettingsService } from '../../../services/settings'

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
  allowNewUserRegistration: false
}

export function createOTPLoginPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: 'otp-login',
    version: '1.0.0-beta.1',
    description: 'Passwordless authentication via email one-time codes'
  })

  builder.metadata({
    author: {
      name: 'SonicJS Team',
      email: 'team@sonicjs.com'
    },
    license: 'MIT',
    compatibility: '^2.0.0'
  })

  // ==================== API Routes ====================

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
        FROM users
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
          appName: siteName
        })

        // Load email plugin settings from database
        // Note: We don't check status='active' because the email plugin's
        // settings UI works regardless of status, so we follow the same pattern
        const emailPlugin = await db.prepare(`
          SELECT settings FROM plugins WHERE id = 'email'
        `).first() as { settings: string | null } | null

        if (emailPlugin?.settings) {
          const emailSettings = JSON.parse(emailPlugin.settings)

          if (emailSettings.apiKey && emailSettings.fromEmail && emailSettings.fromName) {
            // Send email via Resend API
            const emailResponse = await fetch('https://api.resend.com/emails', {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${emailSettings.apiKey}`,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                from: `${emailSettings.fromName} <${emailSettings.fromEmail}>`,
                to: [normalizedEmail],
                subject: `Your login code for ${siteName}`,
                html: emailContent.html,
                text: emailContent.text,
                reply_to: emailSettings.replyTo || emailSettings.fromEmail
              })
            })

            if (!emailResponse.ok) {
              const errorData = await emailResponse.json() as { message?: string }
              console.error('Failed to send OTP email via Resend:', errorData)
              // Don't expose error to user for security - just log it
            }
          } else {
            console.warn('Email plugin is not fully configured (missing apiKey, fromEmail, or fromName)')
          }
        } else {
          console.warn('Email plugin is not active or has no settings configured')
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
      const user = await db.prepare(`
        SELECT id, email, role, is_active
        FROM users
        WHERE email = ?
      `).bind(normalizedEmail).first() as any

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

      // Generate JWT token
      const token = await AuthManager.generateToken(user.id, user.email, user.role, (c.env as any).JWT_SECRET)

      // Set HTTP-only cookie
      setCookie(c, 'auth_token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: 60 * 60 * 24 // 24 hours
      })

      return c.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          role: user.role
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

  // Register API routes
  builder.addRoute('/auth/otp', otpAPI, {
    description: 'OTP authentication endpoints',
    requiresAuth: false,
    priority: 100
  })

  // Note: Admin UI is now handled by the generic plugin settings page
  // with custom component at admin-plugin-settings.template.ts

  // Add menu item (points to generic plugin settings page)
  builder.addMenuItem('OTP Login', '/admin/plugins/otp-login', {
    icon: 'key',
    order: 85,
    permissions: ['otp:manage']
  })

  // Lifecycle hooks
  builder.lifecycle({
    activate: async () => {
      console.info('✅ OTP Login plugin activated')
    },
    deactivate: async () => {
      console.info('❌ OTP Login plugin deactivated')
    }
  })

  return builder.build() as Plugin
}

export const otpLoginPlugin = createOTPLoginPlugin()
