import { Hono, Context } from 'hono';
import { D1Database, KVNamespace, R2Bucket } from '@cloudflare/workers-types';

/**
 * Main Application Factory
 *
 * Creates a configured SonicJS application with all core functionality
 */

interface Bindings {
    DB: D1Database;
    CACHE_KV: KVNamespace;
    MEDIA_BUCKET: R2Bucket;
    ASSETS: Fetcher;
    EMAIL_QUEUE?: Queue;
    SENDGRID_API_KEY?: string;
    DEFAULT_FROM_EMAIL?: string;
    IMAGES_ACCOUNT_ID?: string;
    IMAGES_API_TOKEN?: string;
    ENVIRONMENT?: string;
    CORS_ORIGINS?: string;
    JWT_SECRET?: string;
    BUCKET_NAME?: string;
    GOOGLE_MAPS_API_KEY?: string;
}
interface Variables {
    user?: {
        userId: string;
        email: string;
        role: string;
        exp: number;
        iat: number;
    };
    requestId?: string;
    startTime?: number;
    appVersion?: string;
    csrfToken?: string;
}
interface SonicJSConfig {
    collections?: {
        directory?: string;
        autoSync?: boolean;
    };
    plugins?: {
        directory?: string;
        autoLoad?: boolean;
        disableAll?: boolean;
    };
    routes?: Array<{
        path: string;
        handler: Hono;
    }>;
    middleware?: {
        beforeAuth?: Array<(c: Context, next: () => Promise<void>) => Promise<void>>;
        afterAuth?: Array<(c: Context, next: () => Promise<void>) => Promise<void>>;
    };
    version?: string;
    name?: string;
}
type SonicJSApp = Hono<{
    Bindings: Bindings;
    Variables: Variables;
}>;
/**
 * Create a SonicJS application with core functionality
 *
 * @param config - Application configuration
 * @returns Configured Hono application
 *
 * @example
 * ```typescript
 * import { createSonicJSApp } from '@sonicjs-cms/core'
 *
 * const app = createSonicJSApp({
 *   collections: {
 *     directory: './src/collections',
 *     autoSync: true
 *   },
 *   plugins: {
 *     directory: './src/plugins',
 *     autoLoad: true
 *   }
 * })
 *
 * export default app
 * ```
 */
declare function createSonicJSApp(config?: SonicJSConfig): SonicJSApp;
/**
 * Setup core middleware (backward compatibility)
 *
 * @param _app - Hono application
 * @deprecated Use createSonicJSApp() instead
 */
declare function setupCoreMiddleware(_app: SonicJSApp): void;
/**
 * Setup core routes (backward compatibility)
 *
 * @param _app - Hono application
 * @deprecated Use createSonicJSApp() instead
 */
declare function setupCoreRoutes(_app: SonicJSApp): void;

export { type Bindings as B, type SonicJSConfig as S, type Variables as V, setupCoreRoutes as a, type SonicJSApp as b, createSonicJSApp as c, setupCoreMiddleware as s };
