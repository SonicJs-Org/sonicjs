/**
 * Middleware Module Exports
 *
 * Request processing middleware for SonicJS
 *
 * Note: Most middleware is currently in the monolith and will be migrated later.
 * For now, we only export the bootstrap middleware which is used for system initialization.
 */

// Bootstrap middleware
export { bootstrapMiddleware, verifySecurityConfig } from './bootstrap'

// Auth middleware
export { AuthManager, requireAuth, requireRole, optionalAuth } from './auth'

// Metrics middleware
export { metricsMiddleware } from './metrics'

// CSRF protection middleware
export { csrfProtection, generateCsrfToken, validateCsrfToken } from './csrf'

// Rate limiting middleware
export { rateLimit } from './rate-limit'

// Re-export types and functions that are referenced but implemented in monolith
// These are placeholder exports to maintain API compatibility
export type Permission = string
export type UserPermissions = {
  userId: string
  permissions: Permission[]
}

// Middleware stubs - these return pass-through middleware that call next()
export const loggingMiddleware: any = () => async (_c: any, next: any) => await next()
export const detailedLoggingMiddleware: any = () => async (_c: any, next: any) => await next()
export const securityLoggingMiddleware: any = () => async (_c: any, next: any) => await next()
export const performanceLoggingMiddleware: any = () => async (_c: any, next: any) => await next()
export const cacheHeaders: any = () => async (_c: any, next: any) => await next()
export const compressionMiddleware: any = async (_c: any, next: any) => await next()
export { securityHeadersMiddleware as securityHeaders } from './security-headers'

// Other stubs
export const PermissionManager: any = {}
export const requirePermission: any = () => async (_c: any, next: any) => await next()
export const requireAnyPermission: any = () => async (_c: any, next: any) => await next()
export const logActivity: any = () => {}
export const requireActivePlugin: any = () => async (_c: any, next: any) => await next()
export const requireActivePlugins: any = () => async (_c: any, next: any) => await next()
export const getActivePlugins: any = () => []
export const isPluginActive: any = () => false
