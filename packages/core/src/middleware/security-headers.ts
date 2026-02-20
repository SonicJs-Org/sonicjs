import { Context, Next } from 'hono'

/**
 * Security headers middleware.
 * Sets standard security headers on every response.
 * Skips HSTS in development to avoid local dev issues.
 */
export const securityHeadersMiddleware = () => {
  return async (c: Context, next: Next) => {
    await next()

    c.header('X-Content-Type-Options', 'nosniff')
    c.header('X-Frame-Options', 'SAMEORIGIN')
    c.header('Referrer-Policy', 'strict-origin-when-cross-origin')
    c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')

    // Only set HSTS in non-development environments
    const environment = (c.env as any)?.ENVIRONMENT
    if (environment !== 'development') {
      c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }
  }
}
