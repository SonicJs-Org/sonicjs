import type { Context, Next } from 'hono'
import type { Bindings, Variables } from '../../../../app'
import { SecurityAuditService } from '../services/security-audit-service'
import { BruteForceDetector } from '../services/brute-force-detector'
import { PluginService } from '../../../../services'
import type { SecurityAuditSettings, SecurityEventType } from '../types'
import { DEFAULT_SETTINGS } from '../types'

function extractRequestInfo(c: Context<{ Bindings: Bindings; Variables: Variables }>) {
  const ip = c.req.header('cf-connecting-ip')
    || c.req.header('x-forwarded-for')?.split(',')[0]?.trim()
    || 'unknown'
  const userAgent = c.req.header('user-agent') || 'unknown'
  const countryCode = c.req.header('cf-ipcountry') || null
  const path = new URL(c.req.url).pathname
  const method = c.req.method

  return { ip, userAgent, countryCode, path, method }
}

function generateFingerprint(ip: string, userAgent: string): string {
  // Simple fingerprint from IP + UA - using a basic hash
  const str = `${ip}:${userAgent}`
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash |= 0
  }
  return Math.abs(hash).toString(36)
}

async function getPluginSettings(db: any): Promise<SecurityAuditSettings> {
  try {
    const pluginService = new PluginService(db)
    const plugin = await pluginService.getPlugin('security-audit')
    if (plugin?.settings) {
      const settings = typeof plugin.settings === 'string' ? JSON.parse(plugin.settings) : plugin.settings
      return { ...DEFAULT_SETTINGS, ...settings }
    }
  } catch {
    // Plugin not installed or DB not ready
  }
  return DEFAULT_SETTINGS
}

async function isPluginActive(db: any): Promise<boolean> {
  try {
    const result = await db.prepare(
      "SELECT status FROM plugins WHERE id = 'security-audit'"
    ).first() as { status: string } | null
    return result?.status === 'active'
  } catch {
    return false
  }
}

export function securityAuditMiddleware() {
  return async (c: Context<{ Bindings: Bindings; Variables: Variables }>, next: Next) => {
    const path = new URL(c.req.url).pathname

    // Only intercept auth-related routes
    if (!path.startsWith('/auth/')) {
      return next()
    }

    const db = c.env.DB

    // Check if plugin is active
    if (!await isPluginActive(db)) {
      return next()
    }

    const settings = await getPluginSettings(db)
    const { ip, userAgent, countryCode, method } = extractRequestInfo(c)
    const fingerprint = generateFingerprint(ip, userAgent)

    // For login POST, extract email and check lockout before proceeding
    const isLoginPost = (path === '/auth/login' || path === '/auth/login/form') && method === 'POST'
    let preExtractedEmail = ''

    if (isLoginPost) {
      try {
        if (path === '/auth/login/form') {
          // Form-based login: clone request to read formData without consuming it
          const clonedReq = c.req.raw.clone()
          const formData = await clonedReq.formData()
          preExtractedEmail = (formData.get('email') as string || '').toLowerCase()
        } else {
          // JSON login: Hono caches parsed JSON so this is safe
          const body = await c.req.json()
          preExtractedEmail = body?.email?.toLowerCase() || ''
        }
      } catch {
        // Can't parse body, continue
      }

      if (preExtractedEmail && settings.bruteForce.enabled) {
        const detector = new BruteForceDetector(c.env.CACHE_KV, settings.bruteForce)
        const lockStatus = await detector.isLocked(ip, preExtractedEmail)

        if (lockStatus.locked) {
          const service = new SecurityAuditService(db, settings)
          // Log the blocked attempt asynchronously
          const logPromise = service.logEvent({
            eventType: 'login_failure',
            severity: 'warning',
            email: preExtractedEmail,
            ipAddress: ip,
            userAgent,
            countryCode: countryCode || undefined,
            requestPath: path,
            requestMethod: method,
            fingerprint,
            blocked: true,
            details: { reason: lockStatus.reason }
          })

          if (c.executionCtx?.waitUntil) {
            c.executionCtx.waitUntil(logPromise)
          }

          return c.json({
            error: lockStatus.reason || 'Too many failed attempts. Please try again later.'
          }, 429)
        }
      }
    }

    // Proceed with the request
    await next()

    // After response, log the event asynchronously
    const logPromise = logAuthEvent(c, db, settings, ip, userAgent, countryCode, fingerprint, path, method, preExtractedEmail)

    if (c.executionCtx?.waitUntil) {
      c.executionCtx.waitUntil(logPromise)
    }
  }
}

async function logAuthEvent(
  c: Context<{ Bindings: Bindings; Variables: Variables }>,
  db: any,
  settings: SecurityAuditSettings,
  ip: string,
  userAgent: string,
  countryCode: string | null,
  fingerprint: string,
  path: string,
  method: string,
  preExtractedEmail: string = ''
): Promise<void> {
  try {
    const service = new SecurityAuditService(db, settings)
    const status = c.res.status
    const isLoginPost = (path === '/auth/login' || path === '/auth/login/form') && method === 'POST'
    const isFormLogin = path === '/auth/login/form'

    // Login POST
    if (isLoginPost) {
      // Determine if login succeeded or failed.
      // JSON login: 200 = success, 401/400 = failure
      // Form login: always returns 200 — check if response set an auth cookie (HX-Redirect header indicates success)
      let loginSucceeded: boolean
      if (isFormLogin) {
        // Form login redirects to /admin on success via HX-Redirect header or meta refresh
        const hxRedirect = c.res.headers.get('HX-Redirect')
        const setCookieHeader = c.res.headers.get('set-cookie') || ''
        loginSucceeded = !!(hxRedirect?.includes('/admin') || setCookieHeader.includes('auth_token'))
      } else {
        loginSucceeded = status === 200
      }

      if (loginSucceeded) {
        if (!settings.logging.logSuccessfulLogins) return

        // Try to get user info from response
        let email = preExtractedEmail
        let userId = ''
        if (!isFormLogin) {
          try {
            const cloned = c.res.clone()
            const body = await cloned.json() as any
            email = body?.user?.email || email
            userId = body?.user?.id || ''
          } catch { /* ignore */ }
        }

        await service.logEvent({
          eventType: 'login_success',
          severity: 'info',
          userId: userId || undefined,
          email: email || undefined,
          ipAddress: ip,
          userAgent,
          countryCode: countryCode || undefined,
          requestPath: path,
          requestMethod: method,
          fingerprint
        })
      } else {
        // Failed login — use pre-extracted email since body is already consumed
        const email = preExtractedEmail

        await service.logEvent({
          eventType: 'login_failure',
          severity: 'warning',
          email: email || undefined,
          ipAddress: ip,
          userAgent,
          countryCode: countryCode || undefined,
          requestPath: path,
          requestMethod: method,
          fingerprint,
          details: { statusCode: status }
        })

        // Record failed attempt for brute-force detection
        if (email && settings.bruteForce.enabled) {
          const detector = new BruteForceDetector(c.env.CACHE_KV, settings.bruteForce)
          const result = await detector.recordFailedAttempt(ip, email)

          if (result.shouldLockIP) {
            await detector.lockIP(ip)
            await service.logEvent({
              eventType: 'account_lockout',
              severity: 'critical',
              email,
              ipAddress: ip,
              userAgent,
              countryCode: countryCode || undefined,
              requestPath: path,
              requestMethod: method,
              fingerprint,
              details: { reason: 'brute_force_ip', attemptCount: result.ipCount }
            })
          }

          if (result.shouldLockEmail) {
            await detector.lockEmail(email)
            await service.logEvent({
              eventType: 'account_lockout',
              severity: 'critical',
              email,
              ipAddress: ip,
              userAgent,
              countryCode: countryCode || undefined,
              requestPath: path,
              requestMethod: method,
              fingerprint,
              details: { reason: 'brute_force_email', attemptCount: result.emailCount }
            })
          }

          if (result.isSuspicious) {
            await service.logEvent({
              eventType: 'suspicious_activity',
              severity: 'critical',
              ipAddress: ip,
              userAgent,
              countryCode: countryCode || undefined,
              requestPath: path,
              requestMethod: method,
              fingerprint,
              details: { reason: 'multiple_emails_from_ip', ipCount: result.ipCount }
            })
          }
        }
      }
    }

    // Registration POST
    if (path === '/auth/register' && method === 'POST' && settings.logging.logRegistrations) {
      if (status === 201 || status === 200) {
        let email = ''
        let userId = ''
        try {
          const cloned = c.res.clone()
          const body = await cloned.json() as any
          email = body?.user?.email || ''
          userId = body?.user?.id || ''
        } catch { /* ignore */ }

        await service.logEvent({
          eventType: 'registration',
          severity: 'info',
          userId: userId || undefined,
          email: email || undefined,
          ipAddress: ip,
          userAgent,
          countryCode: countryCode || undefined,
          requestPath: path,
          requestMethod: method,
          fingerprint
        })
      }
    }

    // Logout
    if (path === '/auth/logout' && settings.logging.logLogouts) {
      const user = c.get('user')
      await service.logEvent({
        eventType: 'logout',
        severity: 'info',
        userId: user?.userId,
        email: user?.email,
        ipAddress: ip,
        userAgent,
        countryCode: countryCode || undefined,
        requestPath: path,
        requestMethod: method,
        fingerprint
      })
    }
  } catch (error) {
    console.error('[SecurityAudit] Error logging auth event:', error)
  }
}
