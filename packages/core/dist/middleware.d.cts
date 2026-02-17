import * as hono from 'hono';
import { Context, Next, MiddlewareHandler } from 'hono';
import { S as SonicJSConfig } from './app-3Zr8JaYf.cjs';
import '@cloudflare/workers-types';

type Bindings = {
    DB: D1Database;
    KV: KVNamespace;
};
/**
 * Bootstrap middleware that ensures system initialization
 * Runs once per worker instance
 */
declare function bootstrapMiddleware(config?: SonicJSConfig): (c: Context<{
    Bindings: Bindings;
}>, next: Next) => Promise<void>;

type JWTPayload = {
    userId: string;
    email: string;
    role: string;
    exp: number;
    iat: number;
};
declare class AuthManager {
    static generateToken(userId: string, email: string, role: string): Promise<string>;
    static verifyToken(token: string): Promise<JWTPayload | null>;
    static hashPassword(password: string): Promise<string>;
    static verifyPassword(password: string, hash: string): Promise<boolean>;
    /**
     * Set authentication cookie - useful for plugins implementing alternative auth methods
     * @param c - Hono context
     * @param token - JWT token to set in cookie
     * @param options - Optional cookie configuration
     */
    static setAuthCookie(c: Context, token: string, options?: {
        maxAge?: number;
        secure?: boolean;
        httpOnly?: boolean;
        sameSite?: 'Strict' | 'Lax' | 'None';
    }): void;
}
declare const requireAuth: () => (c: Context, next: Next) => Promise<void | (Response & hono.TypedResponse<undefined, 302, "redirect">) | (Response & hono.TypedResponse<{
    error: string;
}, 401, "json">)>;
declare const requireRole: (requiredRole: string | string[]) => (c: Context, next: Next) => Promise<void | (Response & hono.TypedResponse<undefined, 302, "redirect">) | (Response & hono.TypedResponse<{
    error: string;
}, 401, "json">) | (Response & hono.TypedResponse<{
    error: string;
}, 403, "json">)>;
declare const optionalAuth: () => (c: Context, next: Next) => Promise<void>;

/**
 * Require a valid API key with a specific scope.
 *
 * When `REQUIRE_API_KEY` env var is NOT set, falls back to
 * optionalApiKey() behavior (allow through, validate if present).
 */
declare const requireApiKey: (scope: string) => (c: Context, next: Next) => Promise<void | (Response & hono.TypedResponse<{
    error: string;
}, 403, "json">) | (Response & hono.TypedResponse<{
    error: string;
}, 401, "json">)>;
/**
 * Optionally validate an API key if the X-API-Key header is present.
 * Does NOT block if no key is provided.
 */
declare const optionalApiKey: () => (c: Context, next: Next) => Promise<void>;

/**
 * Middleware to track all HTTP requests for real-time analytics
 * Excludes the metrics endpoint itself to avoid inflating the count
 */
declare const metricsMiddleware: () => MiddlewareHandler;

/**
 * Middleware Module Exports
 *
 * Request processing middleware for SonicJS
 *
 * Note: Most middleware is currently in the monolith and will be migrated later.
 * For now, we only export the bootstrap middleware which is used for system initialization.
 */

type Permission = string;
type UserPermissions = {
    userId: string;
    permissions: Permission[];
};
declare const loggingMiddleware: any;
declare const detailedLoggingMiddleware: any;
declare const securityLoggingMiddleware: any;
declare const performanceLoggingMiddleware: any;
declare const cacheHeaders: any;
declare const compressionMiddleware: any;
declare const securityHeaders: any;
declare const PermissionManager: any;
declare const requirePermission: any;
declare const requireAnyPermission: any;
declare const logActivity: any;
declare const requireActivePlugin: any;
declare const requireActivePlugins: any;
declare const getActivePlugins: any;
declare const isPluginActive: any;

export { AuthManager, type Permission, PermissionManager, type UserPermissions, bootstrapMiddleware, cacheHeaders, compressionMiddleware, detailedLoggingMiddleware, getActivePlugins, isPluginActive, logActivity, loggingMiddleware, metricsMiddleware, optionalApiKey, optionalAuth, performanceLoggingMiddleware, requireActivePlugin, requireActivePlugins, requireAnyPermission, requireApiKey, requireAuth, requirePermission, requireRole, securityHeaders, securityLoggingMiddleware };
