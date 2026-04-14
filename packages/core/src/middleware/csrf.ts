/**
 * CSRF Protection Middleware — Signed Double-Submit Cookie
 *
 * Stateless CSRF protection for Cloudflare Workers (no session store needed).
 * Token format: `<nonce>.<hmac>` where HMAC-SHA256 is keyed with JWT_SECRET.
 *
 * Flow:
 *   GET  — ensureCsrfCookie(): reuse existing valid cookie or set a new one
 *   POST/PUT/DELETE/PATCH — validate X-CSRF-Token header === csrf_token cookie, HMAC valid
 *
 * Exempt:
 *   - Safe methods (GET, HEAD, OPTIONS)
 *   - Auth routes that create sessions (/auth/login*, /auth/register*, etc.)
 *   - Public form submissions (/forms/*, /api/forms/*) — NOT /admin/forms/*
 *   - Requests with no auth_token cookie (Bearer-only or API-key-only)
 */

import type { Context, Next } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'

// Fallback secret — mirrors auth.ts behavior for local dev without wrangler secret
const JWT_SECRET_FALLBACK = 'your-super-secret-jwt-key-change-in-production'

// ============================================================================
// Helpers
// ============================================================================

/** Convert ArrayBuffer to URL-safe base64 (no padding). */
export function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Import a string key for HMAC-SHA256. */
async function getHmacKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder()
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  )
}

// ============================================================================
// Token Generation & Validation
// ============================================================================

/**
 * Generate a signed CSRF token: `<nonce>.<hmac_signature>`
 * - nonce = 32 random bytes, base64url-encoded
 * - signature = HMAC-SHA256(nonce, secret), base64url-encoded
 */
export async function generateCsrfToken(secret: string): Promise<string> {
  const nonceBytes = new Uint8Array(32)
  crypto.getRandomValues(nonceBytes)
  const nonce = arrayBufferToBase64Url(nonceBytes.buffer)

  const key = await getHmacKey(secret)
  const encoder = new TextEncoder()
  const signatureBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(nonce))
  const signature = arrayBufferToBase64Url(signatureBuffer)

  return `${nonce}.${signature}`
}

/**
 * Validate a signed CSRF token.
 *
 * Checks that the token has the correct `<nonce>.<signature>` format and that
 * the HMAC signature is valid for the given secret. Uses crypto.subtle.verify
 * which provides constant-time comparison.
 *
 * NOTE: No expiry check here — by design. The security property of signed
 * double-submit comes from the unpredictability of the nonce + the
 * secret-bound HMAC, not from time-bounding. The cookie's maxAge (86400s)
 * handles expiry at the browser level.
 */
export async function validateCsrfToken(token: string, secret: string): Promise<boolean> {
  if (!token || typeof token !== 'string') return false

  const dotIndex = token.indexOf('.')
  if (dotIndex === -1) return false

  const nonce = token.substring(0, dotIndex)
  const signature = token.substring(dotIndex + 1)

  if (!nonce || !signature) return false

  try {
    const key = await getHmacKey(secret)
    const encoder = new TextEncoder()

    // Decode the signature from base64url
    const sigPadded = signature.replace(/-/g, '+').replace(/_/g, '/')
    const sigBinary = atob(sigPadded)
    const sigBytes = new Uint8Array(sigBinary.length)
    for (let i = 0; i < sigBinary.length; i++) {
      sigBytes[i] = sigBinary.charCodeAt(i)
    }

    // crypto.subtle.verify is constant-time
    return await crypto.subtle.verify('HMAC', key, sigBytes.buffer, encoder.encode(nonce))
  } catch {
    return false
  }
}

// ============================================================================
// Default Exempt Paths
// ============================================================================

const DEFAULT_EXEMPT_PATHS = [
  '/auth/login',
  '/auth/register',
  '/auth/seed-admin',
  '/auth/accept-invitation',
  '/auth/reset-password',
  '/auth/request-password-reset',
  '/auth/otp',
  '/auth/magic-link',
  '/auth/verify',
  '/api/stripe/webhook',
  '/api/events',
]

/**
 * Check whether a request path is exempt from CSRF validation.
 * - Exact match or startsWith for auth routes (e.g. /auth/login/form)
 * - /forms/* and /api/forms/* are exempt (public submissions)
 * - /api/search* is exempt (read-only POST for complex query params)
 * - /admin/forms/* is NOT exempt
 */
function isExemptPath(path: string, extraExemptPaths: string[] = []): boolean {
  // Public form routes — NOT /admin/forms/*
  if (path.startsWith('/forms/') || path.startsWith('/api/forms/') || path === '/forms' || path === '/api/forms') {
    return true
  }

  // Search API — read-only POST (includes /api/search/click, /api/search/facet-click)
  if (path.startsWith('/api/search')) {
    return true
  }

  const allExempt = [...DEFAULT_EXEMPT_PATHS, ...extraExemptPaths]
  for (const exempt of allExempt) {
    if (path === exempt || path.startsWith(exempt + '/')) {
      return true
    }
  }

  return false
}

// ============================================================================
// Middleware
// ============================================================================

export interface CsrfOptions {
  /** Additional paths to exempt from CSRF validation. */
  exemptPaths?: string[]
}

/**
 * CSRF protection middleware (Signed Double-Submit Cookie).
 *
 * - GET/HEAD/OPTIONS: ensure a valid csrf_token cookie exists
 * - POST/PUT/DELETE/PATCH: validate X-CSRF-Token header matches cookie, HMAC valid
 * - Exempt: auth routes, public /forms/*, Bearer-only, API-key-only
 */
export function csrfProtection(options: CsrfOptions = {}) {
  return async (c: Context, next: Next): Promise<Response | void> => {
    const method = c.req.method.toUpperCase()
    const path = new URL(c.req.url).pathname
    const secret = c.env?.JWT_SECRET || JWT_SECRET_FALLBACK

    // Warn if using fallback secret in production
    if (c.env?.ENVIRONMENT === 'production' && !c.env?.JWT_SECRET) {
      console.warn(
        '[CSRF] WARNING: JWT_SECRET is not set in production. ' +
        'CSRF tokens are signed with the fallback key, which is insecure.'
      )
    }

    // Safe methods — just ensure cookie, then pass through
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
      await ensureCsrfCookie(c, secret)
      await next()
      return
    }

    // Exempt paths — pass through without validation
    if (isExemptPath(path, options.exemptPaths)) {
      await next()
      return
    }

    // Bearer-only or API-key-only requests (no auth_token cookie) — exempt
    const authCookie = getCookie(c, 'auth_token')
    if (!authCookie) {
      await next()
      return
    }

    // Requests with an Authorization header use token-based auth — the cookie
    // is incidental and CSRF protection is unnecessary (the attacker cannot
    // forge the Authorization header from a cross-origin page).
    const authHeader = c.req.header('Authorization')
    if (authHeader) {
      await next()
      return
    }

    // State-changing request with cookie auth — validate CSRF
    const cookieToken = getCookie(c, 'csrf_token')
    let headerToken = c.req.header('X-CSRF-Token')

    // Fallback: check _csrf field in form-encoded body (regular HTML form submissions)
    if (!headerToken) {
      const contentType = c.req.header('Content-Type') || ''
      if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
        try {
          const body = await c.req.parseBody()
          headerToken = body['_csrf'] as string | undefined
        } catch {
          // Body not parseable — leave headerToken undefined
        }
      }
    }

    if (!cookieToken || !headerToken) {
      return csrfError(c, 'CSRF token missing')
    }

    if (cookieToken !== headerToken) {
      return csrfError(c, 'CSRF token mismatch')
    }

    const isValid = await validateCsrfToken(cookieToken, secret)
    if (!isValid) {
      return csrfError(c, 'CSRF token invalid')
    }

    await next()
  }
}

/**
 * Ensure a valid CSRF cookie exists. Check-then-reuse: if the existing cookie
 * has a valid HMAC signature, reuse it (no new Set-Cookie header). Only
 * generate a fresh token when the cookie is missing or has an invalid signature.
 */
async function ensureCsrfCookie(c: Context, secret: string): Promise<void> {
  const existing = getCookie(c, 'csrf_token')

  if (existing) {
    const isValid = await validateCsrfToken(existing, secret)
    if (isValid) {
      // Reuse existing valid token — no Set-Cookie needed
      c.set('csrfToken', existing)
      return
    }
  }

  // Generate fresh token
  const token = await generateCsrfToken(secret)
  c.set('csrfToken', token)

  const isDev = c.env?.ENVIRONMENT === 'development' || !c.env?.ENVIRONMENT
  setCookie(c, 'csrf_token', token, {
    httpOnly: false,  // JS must read this cookie
    secure: !isDev,
    sameSite: 'Strict',
    path: '/',
    maxAge: 86400,    // 24 hours — browser-side expiry
  })
}

/** Return a 403 CSRF error — HTML for browser requests, JSON for API. */
function csrfError(c: Context, message: string): Response {
  const accept = c.req.header('Accept') || ''
  if (accept.includes('text/html')) {
    return c.html(
      `<!DOCTYPE html><html><head><title>403 Forbidden</title></head>` +
      `<body><h1>403 Forbidden</h1><p>${message}</p></body></html>`,
      403
    )
  }
  return c.json({ error: message, status: 403 }, 403)
}
