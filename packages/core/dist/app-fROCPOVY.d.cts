import * as zod from 'zod';
import * as better_call from 'better-call';
import * as better_auth_cloudflare from 'better-auth-cloudflare';
import * as better_auth from 'better-auth';
import { Hono, Context } from 'hono';
import { D1Database, KVNamespace, R2Bucket } from '@cloudflare/workers-types';

/**
 * Build the default Better Auth options used by SonicJS (through the CF shim).
 * Exported so apps can extend via config.auth.extendBetterAuth.
 */
declare function getDefaultAuthOptions(env: Bindings): {
    user: {
        modelName: "users";
        fields: {
            image: string;
        };
        additionalFields: {
            role: {
                type: "string";
                required: false;
                defaultValue: string;
                input: false;
            };
            username: {
                type: "string";
                required: false;
                defaultValue: string;
                input: true;
            };
            firstName: {
                type: "string";
                required: false;
                defaultValue: string;
                input: true;
            };
            lastName: {
                type: "string";
                required: false;
                defaultValue: string;
                input: true;
            };
        };
    };
    session: {
        modelName: "session";
        expiresIn: number;
        updateAge: number;
    };
    account: {
        modelName: "account";
    };
    verification: {
        modelName: "verification";
    };
    basePath: string;
    emailAndPassword: {
        enabled: true;
        autoSignIn: true;
        password: {
            verify: ({ hash, password }: {
                hash: string;
                password: string;
            }) => Promise<boolean>;
        };
    };
    databaseHooks: {
        user: {
            create: {
                before: (userData: Record<string, unknown>) => Promise<{
                    data: {
                        name: string;
                        firstName: string;
                        lastName: string;
                        username: string;
                        role: string;
                    };
                }>;
                after: (user: {
                    id: string;
                }) => Promise<void>;
            };
        };
    };
    plugins: [{
        id: "cloudflare";
        schema: better_auth.BetterAuthPluginDBSchema;
        endpoints: {
            upload?: better_call.StrictEndpoint<"/files/upload-raw", {
                method: "POST";
                metadata: {
                    allowedMediaTypes: string[] | undefined;
                };
            }, {
                success: boolean;
                data: better_auth_cloudflare.FileMetadata;
            }> | undefined;
            download?: better_call.StrictEndpoint<"/files/download", {
                method: "POST";
                use: ((inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>)[];
                body: zod.ZodObject<{
                    fileId: zod.ZodString;
                }, better_auth.$strip>;
            }, Response> | undefined;
            delete?: better_call.StrictEndpoint<"/files/delete", {
                method: "POST";
                use: ((inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>)[];
                body: zod.ZodObject<{
                    fileId: zod.ZodString;
                }, better_auth.$strip>;
            }, {
                message: string;
                fileId: string;
            }> | undefined;
            list?: better_call.StrictEndpoint<"/files/list", {
                method: "GET";
                use: ((inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>)[];
            }, {
                files: better_auth_cloudflare.FileMetadata[];
                nextCursor: string | null;
                hasMore: boolean;
            }> | undefined;
            get?: better_call.StrictEndpoint<"/files/get", {
                method: "POST";
                use: ((inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>)[];
                body: zod.ZodObject<{
                    fileId: zod.ZodString;
                }, better_auth.$strip>;
            }, {
                data: {};
            }> | undefined;
            getGeolocation: better_call.StrictEndpoint<"/cloudflare/geolocation", {
                method: "GET";
            }, better_auth_cloudflare.CloudflareGeolocation | {
                error: string;
            }>;
        };
        init(init_ctx: better_auth.AuthContext): {
            options: {
                databaseHooks: {
                    session: {
                        create: {
                            before: (s: better_auth.Session & Record<string, unknown>, _context: better_auth.GenericEndpointContext | null) => Promise<{
                                data: {
                                    timezone?: string | null;
                                    city?: string | null;
                                    country?: string | null;
                                    region?: string | null;
                                    regionCode?: string | null;
                                    colo?: string | null;
                                    latitude?: string | null;
                                    longitude?: string | null;
                                    id: string;
                                    createdAt: Date;
                                    updatedAt: Date;
                                    userId: string;
                                    expiresAt: Date;
                                    token: string;
                                    ipAddress?: string | null | undefined;
                                    userAgent?: string | null | undefined;
                                };
                            } | undefined>;
                        };
                    };
                };
            };
        };
    }];
    secret: string | undefined;
    baseURL: string | undefined;
    appName: string;
};
type BetterAuthDefaultOptions = ReturnType<typeof getDefaultAuthOptions>;
type ExtendBetterAuth = (opts: BetterAuthDefaultOptions) => BetterAuthDefaultOptions;

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
    JWT_EXPIRES_IN?: string;
    JWT_REFRESH_GRACE_SECONDS?: string;
    BUCKET_NAME?: string;
    GOOGLE_MAPS_API_KEY?: string;
    BETTER_AUTH_SECRET?: string;
    BETTER_AUTH_URL?: string;
}
interface Variables {
    user?: {
        userId: string;
        email: string;
        role: string;
        exp: number;
        iat: number;
    };
    session?: {
        id: string;
        userId: string;
        token: string;
        expiresAt: number;
        createdAt: number;
        updatedAt: number;
    };
    requestId?: string;
    startTime?: number;
    appVersion?: string;
    csrfToken?: string;
    pluginMenuItems?: Array<{
        label: string;
        path: string;
        icon: string;
    }>;
    rbacPerms?: string[];
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
    auth?: {
        extendBetterAuth?: ExtendBetterAuth;
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

export { type Bindings as B, type SonicJSConfig as S, type Variables as V, type SonicJSApp as a, setupCoreRoutes as b, createSonicJSApp as c, setupCoreMiddleware as s };
