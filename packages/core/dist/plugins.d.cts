export { H as HookSystemImpl, a as HookUtils, P as PluginManager, b as PluginRegistryImpl, c as PluginValidator, S as ScopedHookSystem } from './plugin-manager-GcIeb226.cjs';
import { D1Database } from '@cloudflare/workers-types';
import * as hono from 'hono';
import { Context, Next } from 'hono';
import './plugin-0Xogrln-.cjs';
import 'zod';

interface TurnstileSettings {
    siteKey: string;
    secretKey: string;
    theme?: 'light' | 'dark' | 'auto';
    size?: 'normal' | 'compact';
    mode?: 'managed' | 'non-interactive' | 'invisible';
    appearance?: 'always' | 'execute' | 'interaction-only';
    preClearance?: boolean;
    preClearanceLevel?: 'interactive' | 'managed' | 'non-interactive';
    enabled: boolean;
}
declare class TurnstileService {
    private db;
    private readonly VERIFY_URL;
    constructor(db: D1Database);
    /**
     * Get Turnstile settings from database
     */
    getSettings(): Promise<TurnstileSettings | null>;
    /**
     * Verify a Turnstile token with Cloudflare
     */
    verifyToken(token: string, remoteIp?: string): Promise<{
        success: boolean;
        error?: string;
    }>;
    /**
     * Save Turnstile settings to database
     */
    saveSettings(settings: TurnstileSettings): Promise<void>;
    /**
     * Check if Turnstile is enabled
     */
    isEnabled(): Promise<boolean>;
}

/**
 * Middleware to verify Turnstile token on form submissions
 *
 * Usage:
 * ```typescript
 * import { verifyTurnstile } from '@sonicjs-cms/core/plugins'
 *
 * app.post('/api/contact', verifyTurnstile, async (c) => {
 *   // Token already verified, process form...
 * })
 * ```
 */
declare function verifyTurnstile(c: Context, next: Next): Promise<void | (Response & hono.TypedResponse<{
    error: string;
}, 500, "json">) | (Response & hono.TypedResponse<{
    error: string;
    message: string;
}, 400, "json">) | (Response & hono.TypedResponse<{
    error: string;
    message: string;
}, 403, "json">)>;
/**
 * Middleware factory that allows custom error handling
 */
declare function createTurnstileMiddleware(options?: {
    onError?: (c: Context, error: string) => Response;
    onMissing?: (c: Context) => Response;
}): (c: Context, next: Next) => Promise<void | Response>;

export { TurnstileService, createTurnstileMiddleware, verifyTurnstile };
