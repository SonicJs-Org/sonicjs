import { sign, verify } from 'hono/jwt'
import { Context, Next } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'

type JWTPayload = {
  userId: string
  email: string
  role: string
  exp: number
  iat: number
}

// Fallback JWT secret for local development only (no wrangler secret set)
const JWT_SECRET_FALLBACK = 'your-super-secret-jwt-key-change-in-production'

// Default JWT TTL: 30 days. Can be overridden via JWT_EXPIRES_IN env var.
const DEFAULT_JWT_EXPIRES_IN_SECONDS = 60 * 60 * 24 * 30

/**
 * Parse a TTL string like "30d", "12h", "3600s", or a bare number-of-seconds
 * into a seconds value. Returns null if the input is missing/unparseable.
 */
function parseDuration(input: string | number | undefined | null): number | null {
  if (input === undefined || input === null || input === '') return null
  if (typeof input === 'number' && Number.isFinite(input) && input > 0) {
    return Math.floor(input)
  }
  const raw = String(input).trim()
  if (/^\d+$/.test(raw)) {
    const n = parseInt(raw, 10)
    return n > 0 ? n : null
  }
  const match = raw.match(/^(\d+)\s*(s|sec|secs|seconds|m|min|mins|minutes|h|hr|hrs|hours|d|day|days)$/i)
  if (!match) return null
  const value = parseInt(match[1]!, 10)
  const unit = match[2]!.toLowerCase()
  if (unit.startsWith('s')) return value
  if (unit.startsWith('m')) return value * 60
  if (unit.startsWith('h')) return value * 60 * 60
  if (unit.startsWith('d')) return value * 60 * 60 * 24
  return null
}

/**
 * Resolve the JWT expiry in seconds from the environment.
 * Honors `JWT_EXPIRES_IN` (seconds or "30d"/"12h"/"3600s") with a 30-day default.
 */
export function getJwtExpirySeconds(env?: Record<string, any> | null): number {
  const configured = parseDuration(env?.JWT_EXPIRES_IN)
  return configured ?? DEFAULT_JWT_EXPIRES_IN_SECONDS
}

/**
 * Resolve the JWT expiry in seconds. Precedence: `JWT_EXPIRES_IN` env var
 * (authoritative ceiling) → `settings.security.jwtExpiresIn` DB value
 * (admin-configurable) → 30-day default.
 *
 * The env var wins so operators can cap runtime overrides — admins can adjust
 * the TTL from /admin/settings/security, but an env var, if set, always wins.
 * DB failures fall back to env/default so auth never breaks if the settings
 * table is unreachable.
 */
export async function getJwtExpirySecondsFromDb(
  db: { prepare: (query: string) => any } | null | undefined,
  env?: Record<string, any> | null
): Promise<number> {
  const envParsed = parseDuration(env?.JWT_EXPIRES_IN)
  if (envParsed) return envParsed

  if (db) {
    try {
      const row = await db
        .prepare("SELECT value FROM settings WHERE category = 'security' AND key = 'jwtExpiresIn'")
        .first() as { value: string } | null
      if (row?.value) {
        let stored: any = row.value
        try { stored = JSON.parse(row.value) } catch { /* value may already be a bare string */ }
        const parsed = parseDuration(stored)
        if (parsed) return parsed
      }
    } catch (err) {
      console.warn('Failed to read jwtExpiresIn from settings, falling back to default:', err)
    }
  }
  return DEFAULT_JWT_EXPIRES_IN_SECONDS
}

/**
 * Resolve the refresh grace window (seconds) for `/auth/refresh`. Precedence:
 * `JWT_REFRESH_GRACE_SECONDS` env var → `settings.security.jwtRefreshGraceSeconds`
 * DB value → 7-day default.
 */
export async function getJwtRefreshGraceSecondsFromDb(
  db: { prepare: (query: string) => any } | null | undefined,
  env?: Record<string, any> | null
): Promise<number> {
  const DEFAULT_GRACE = 60 * 60 * 24 * 7
  const envParsed = parseDuration(env?.JWT_REFRESH_GRACE_SECONDS)
  if (envParsed) return envParsed

  if (db) {
    try {
      const row = await db
        .prepare("SELECT value FROM settings WHERE category = 'security' AND key = 'jwtRefreshGraceSeconds'")
        .first() as { value: string } | null
      if (row?.value) {
        let stored: any = row.value
        try { stored = JSON.parse(row.value) } catch { /* may be bare */ }
        const parsed = parseDuration(stored)
        if (parsed) return parsed
      }
    } catch (err) {
      console.warn('Failed to read jwtRefreshGraceSeconds from settings:', err)
    }
  }
  return DEFAULT_GRACE
}

/**
 * Decode a JWT payload without verifying the signature. Returns null on any
 * parsing failure. Callers MUST independently verify the signature before
 * trusting this value — used from the grace-window refresh path where the
 * signature is verified explicitly via `verifyHs256Signature`.
 */
function decodeJwtPayload(token: string): JWTPayload | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const b64 = parts[1]!.replace(/-/g, '+').replace(/_/g, '/')
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4)
    const json = atob(padded)
    const obj = JSON.parse(json)
    if (!obj || typeof obj.exp !== 'number') return null
    return obj as JWTPayload
  } catch {
    return null
  }
}

function base64UrlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/')
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4)
  const bin = atob(padded)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

/**
 * Verify a JWT's HS256 signature using Web Crypto, independent of hono/jwt.
 * Returns true iff the signature matches the header.payload portion.
 */
async function verifyHs256Signature(token: string, secret: string): Promise<boolean> {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return false
    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    )
    const signature = base64UrlToBytes(parts[2]!)
    const message = encoder.encode(`${parts[0]}.${parts[1]}`)
    return await crypto.subtle.verify('HMAC', key, signature, message)
  } catch {
    return false
  }
}

export class AuthManager {
  static async generateToken(
    userId: string,
    email: string,
    role: string,
    secret?: string,
    expiresInSeconds?: number
  ): Promise<string> {
    const ttl = expiresInSeconds && expiresInSeconds > 0
      ? Math.floor(expiresInSeconds)
      : DEFAULT_JWT_EXPIRES_IN_SECONDS
    const now = Math.floor(Date.now() / 1000)
    const payload: JWTPayload = {
      userId,
      email,
      role,
      exp: now + ttl,
      iat: now
    }

    return await sign(payload, secret || JWT_SECRET_FALLBACK, 'HS256')
  }

  /**
   * Verify a token's signature and expiration.
   *
   * IMPORTANT: pass the `JWT_SECRET` binding (e.g. `c.env.JWT_SECRET`) as the
   * `secret` argument. If omitted, this falls back to a development-only
   * placeholder secret — tokens signed with the real `JWT_SECRET` will then
   * silently fail verification. From inside a Hono handler prefer
   * `AuthManager.verifyAuthRequest(c)`, which handles header/cookie extraction
   * and pulls the secret from `c.env` for you.
   *
   * If `graceSeconds` > 0, tokens whose `exp` is within the grace window
   * (i.e. expired by no more than `graceSeconds`) are still returned. This
   * supports a sliding-session refresh endpoint that accepts recently-expired
   * tokens. Signature failures always return null.
   */
  static async verifyToken(
    token: string,
    secret?: string,
    graceSeconds: number = 0
  ): Promise<JWTPayload | null> {
    const effectiveSecret = secret || JWT_SECRET_FALLBACK
    try {
      let payload: JWTPayload | null = null
      try {
        payload = await verify(token, effectiveSecret, 'HS256') as JWTPayload
      } catch (verifyError: any) {
        // hono/jwt checks `exp` before signature, so a bad-signature token
        // that happens to be expired will throw JwtTokenExpired here. For
        // the grace window, we still require a valid HS256 signature before
        // accepting the payload.
        const name = verifyError?.name || ''
        const message = String(verifyError?.message || '')
        const isExpired = name === 'JwtTokenExpired' || message.includes('expired')
        if (!isExpired || graceSeconds <= 0) {
          throw verifyError
        }
        const signatureValid = await verifyHs256Signature(token, effectiveSecret)
        if (!signatureValid) return null
        const decoded = decodeJwtPayload(token)
        if (!decoded) return null
        payload = decoded
      }

      if (!payload) return null

      const now = Math.floor(Date.now() / 1000)
      if (payload.exp < now - Math.max(0, Math.floor(graceSeconds))) {
        return null
      }

      return payload
    } catch (error) {
      console.error('Token verification failed:', error)
      return null
    }
  }

  /**
   * Verify the JWT on an incoming Hono request using the `JWT_SECRET`
   * binding from `c.env`. Reads the token from the `Authorization: Bearer …`
   * header first, then falls back to the `auth_token` cookie. Returns the
   * decoded payload, or null when the token is missing, malformed, expired,
   * or signed with a different secret.
   *
   * Use this from custom Hono routes mounted alongside SonicJS — it
   * resolves the secret the same way `requireAuth()` does, without forcing
   * the caller to plumb it through manually.
   */
  static async verifyAuthRequest(c: Context): Promise<JWTPayload | null> {
    let token = c.req.header('Authorization')?.replace('Bearer ', '')
    if (!token) {
      token = getCookie(c, 'auth_token')
    }
    if (!token) return null
    const secret = (c.env as any)?.JWT_SECRET
    return await AuthManager.verifyToken(token, secret)
  }

  static async hashPassword(password: string): Promise<string> {
    const iterations = 100000
    const salt = new Uint8Array(16)
    crypto.getRandomValues(salt)

    const encoder = new TextEncoder()
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    )

    const hashBuffer = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    )

    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
    const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('')

    return `pbkdf2:${iterations}:${saltHex}:${hashHex}`
  }

  static async hashPasswordLegacy(password: string): Promise<string> {
    const encoder = new TextEncoder()
    const data = encoder.encode(password + 'salt-change-in-production')
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  }

  static async verifyPassword(password: string, storedHash: string): Promise<boolean> {
    if (storedHash.startsWith('pbkdf2:')) {
      // PBKDF2 format: pbkdf2:<iterations>:<salt_hex>:<hash_hex>
      const parts = storedHash.split(':')
      if (parts.length !== 4) return false

      const iterationsStr = parts[1]!
      const saltHex = parts[2]!
      const expectedHashHex = parts[3]!
      const iterations = parseInt(iterationsStr, 10)

      const saltBytes = saltHex.match(/.{2}/g)
      if (!saltBytes) return false
      const salt = new Uint8Array(saltBytes.map(byte => parseInt(byte, 16)))

      const encoder = new TextEncoder()
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
      )

      const hashBuffer = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt,
          iterations,
          hash: 'SHA-256'
        },
        keyMaterial,
        256
      )

      const actualHashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('')

      // Constant-time comparison
      if (actualHashHex.length !== expectedHashHex.length) return false
      let result = 0
      for (let i = 0; i < actualHashHex.length; i++) {
        result |= actualHashHex.charCodeAt(i) ^ expectedHashHex.charCodeAt(i)
      }
      return result === 0
    }

    // Legacy SHA-256 format (no colons in hash)
    const legacyHash = await this.hashPasswordLegacy(password)
    // Constant-time comparison for legacy too
    if (legacyHash.length !== storedHash.length) return false
    let result = 0
    for (let i = 0; i < legacyHash.length; i++) {
      result |= legacyHash.charCodeAt(i) ^ storedHash.charCodeAt(i)
    }
    return result === 0
  }

  static isLegacyHash(storedHash: string): boolean {
    return !storedHash.startsWith('pbkdf2:')
  }

  /**
   * Set authentication cookie - useful for plugins implementing alternative auth methods
   * @param c - Hono context
   * @param token - JWT token to set in cookie
   * @param options - Optional cookie configuration
   */
  static setAuthCookie(c: Context, token: string, options?: {
    maxAge?: number
    secure?: boolean
    httpOnly?: boolean
    sameSite?: 'Strict' | 'Lax' | 'None'
  }): void {
    setCookie(c, 'auth_token', token, {
      httpOnly: options?.httpOnly ?? true,
      secure: options?.secure ?? true,
      sameSite: options?.sameSite ?? 'Strict',
      maxAge: options?.maxAge ?? getJwtExpirySeconds((c as any)?.env)
    })
  }
}

// Middleware to require authentication
export const requireAuth = () => {
  return async (c: Context, next: Next) => {
    try {
      // Try to get token from Authorization header
      let token = c.req.header('Authorization')?.replace('Bearer ', '')

      // If no header token, try cookie
      if (!token) {
        token = getCookie(c, 'auth_token')
      }

      if (!token) {
        // Check if this is a browser request (HTML accept header)
        const acceptHeader = c.req.header('Accept') || ''
        if (acceptHeader.includes('text/html')) {
          return c.redirect('/auth/login?error=Please login to access the admin area')
        }
        return c.json({ error: 'Authentication required' }, 401)
      }

      // Try to get cached token verification from KV
      const kv = c.env?.KV
      let payload: JWTPayload | null = null

      if (kv) {
        const cacheKey = `auth:${token.substring(0, 20)}` // Use token prefix as key
        const cached = await kv.get(cacheKey, 'json')
        if (cached) {
          payload = cached as JWTPayload
        }
      }

      // If not cached, verify token
      if (!payload) {
        const jwtSecret = (c.env as any)?.JWT_SECRET
        payload = await AuthManager.verifyToken(token, jwtSecret)

        // Cache the verified payload for 5 minutes
        if (payload && kv) {
          const cacheKey = `auth:${token.substring(0, 20)}`
          await kv.put(cacheKey, JSON.stringify(payload), { expirationTtl: 300 })
        }
      }

      if (!payload) {
        // Check if this is a browser request (HTML accept header)
        const acceptHeader = c.req.header('Accept') || ''
        if (acceptHeader.includes('text/html')) {
          return c.redirect('/auth/login?error=Your session has expired, please login again')
        }
        return c.json({ error: 'Invalid or expired token' }, 401)
      }

      // Add user info to context
      c.set('user', payload)

      return await next()
    } catch (error) {
      console.error('Auth middleware error:', error)
      // Check if this is a browser request (HTML accept header)
      const acceptHeader = c.req.header('Accept') || ''
      if (acceptHeader.includes('text/html')) {
        return c.redirect('/auth/login?error=Authentication failed, please login again')
      }
      return c.json({ error: 'Authentication failed' }, 401)
    }
  }
}

// Middleware to require specific role
export const requireRole = (requiredRole: string | string[]) => {
  return async (c: Context, next: Next) => {
    const user = c.get('user') as JWTPayload
    
    if (!user) {
      // Check if this is a browser request (HTML accept header)
      const acceptHeader = c.req.header('Accept') || ''
      if (acceptHeader.includes('text/html')) {
        return c.redirect('/auth/login?error=Please login to access the admin area')
      }
      return c.json({ error: 'Authentication required' }, 401)
    }
    
    const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole]
    
    if (!roles.includes(user.role)) {
      // Check if this is a browser request (HTML accept header)
      const acceptHeader = c.req.header('Accept') || ''
      if (acceptHeader.includes('text/html')) {
        return c.redirect('/auth/login?error=You do not have permission to access this area')
      }
      return c.json({ error: 'Insufficient permissions' }, 403)
    }
    
    return await next()
  }
}

// Optional auth middleware (doesn't block if no token)
export const optionalAuth = () => {
  return async (c: Context, next: Next) => {
    try {
      let token = c.req.header('Authorization')?.replace('Bearer ', '')
      
      if (!token) {
        token = getCookie(c, 'auth_token')
      }
      
      if (token) {
        const jwtSecret = (c.env as any)?.JWT_SECRET
        const payload = await AuthManager.verifyToken(token, jwtSecret)
        if (payload) {
          c.set('user', payload)
        }
      }
      
      return await next()
    } catch (error) {
      // Don't block on auth errors in optional auth
      console.error('Optional auth error:', error)
      return await next()
    }
  }
}
