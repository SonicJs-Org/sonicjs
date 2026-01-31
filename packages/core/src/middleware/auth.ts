import type { Context, Next } from 'hono'
import { setCookie } from 'hono/cookie'

/** User shape set by Better Auth session middleware (compatibility with c.get('user')) */
export type AuthUserPayload = {
  userId: string
  email: string
  role: string
  exp: number
  iat: number
}

/**
 * AuthManager: legacy helpers for seed-admin and plugins.
 * Main auth is handled by Better Auth; session is set by global middleware.
 */
export class AuthManager {
  /**
   * @deprecated Use Better Auth for sign-in. Kept for seed-admin and plugin compatibility.
   */
  static async generateToken(_userId: string, _email: string, _role: string): Promise<string> {
    throw new Error('Use Better Auth for authentication. JWT generation is deprecated.')
  }

  /**
   * @deprecated Session is verified by Better Auth. Kept for type compatibility.
   */
  static async verifyToken(_token: string): Promise<AuthUserPayload | null> {
    return null
  }

  /** Password hashing for seed-admin (Better Auth uses its own hashing for normal sign-up/sign-in). */
  static async hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder()
    const data = encoder.encode(password + 'salt-change-in-production')
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  }

  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    const passwordHash = await this.hashPassword(password)
    return passwordHash === hash
  }

  /**
   * Set authentication cookie - useful for plugins implementing alternative auth methods.
   * @deprecated Better Auth sets its own session cookie. Kept for plugin compatibility.
   */
  static setAuthCookie(
    c: Context,
    token: string,
    options?: {
      maxAge?: number
      secure?: boolean
      httpOnly?: boolean
      sameSite?: 'Strict' | 'Lax' | 'None'
    }
  ): void {
    setCookie(c, 'auth_token', token, {
      httpOnly: options?.httpOnly ?? true,
      secure: options?.secure ?? true,
      sameSite: options?.sameSite ?? 'Strict',
      maxAge: options?.maxAge ?? 60 * 60 * 24
    })
  }
}

/** Require authentication. Relies on global session middleware to set c.set('user'). */
export const requireAuth = () => {
  return async (c: Context, next: Next) => {
    const user = c.get('user') as AuthUserPayload | undefined
    if (!user) {
      const acceptHeader = c.req.header('Accept') ?? ''
      if (acceptHeader.includes('text/html')) {
        return c.redirect('/auth/login?error=Please login to access the admin area')
      }
      return c.json({ error: 'Authentication required' }, 401)
    }
    return await next()
  }
}

/** Require specific role. Must run after requireAuth or session middleware. */
export const requireRole = (requiredRole: string | string[]) => {
  return async (c: Context, next: Next) => {
    const user = c.get('user') as AuthUserPayload | undefined
    if (!user) {
      const acceptHeader = c.req.header('Accept') ?? ''
      if (acceptHeader.includes('text/html')) {
        return c.redirect('/auth/login?error=Please login to access the admin area')
      }
      return c.json({ error: 'Authentication required' }, 401)
    }
    const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole]
    if (!roles.includes(user.role)) {
      const acceptHeader = c.req.header('Accept') ?? ''
      if (acceptHeader.includes('text/html')) {
        return c.redirect('/auth/login?error=You do not have permission to access this area')
      }
      return c.json({ error: 'Insufficient permissions' }, 403)
    }
    return await next()
  }
}

/** Optional auth: user may already be set by global session middleware; no-op if not. */
export const optionalAuth = () => {
  return async (c: Context, next: Next) => {
    await next()
  }
}
