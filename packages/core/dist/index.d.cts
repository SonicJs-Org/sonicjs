export { B as Bindings, a as SonicJSApp, S as SonicJSConfig, V as Variables, c as createSonicJSApp, s as setupCoreMiddleware, b as setupCoreRoutes } from './app-COElO4Rm.cjs';
import { B as schema } from './plugin-bootstrap-DfVerYV4.cjs';
export { D as Collection, E as Content, C as CorePlugin, F as DbPlugin, G as DbPluginHook, L as LogCategory, H as LogConfig, a as LogEntry, b as LogFilter, c as LogLevel, d as Logger, I as Media, M as Migration, e as MigrationService, f as MigrationStatus, N as NewCollection, J as NewContent, K as NewLogConfig, O as NewMedia, Q as NewPlugin, R as NewPluginActivityLog, S as NewPluginAsset, T as NewPluginHook, U as NewPluginRoute, V as NewSystemLog, W as NewUser, X as NewWorkflowHistory, Y as PluginActivityLog, Z as PluginAsset, P as PluginBootstrapService, _ as PluginRoute, g as PluginServiceClass, $ as SystemLog, a0 as User, a1 as WorkflowHistory, a2 as apiTokens, h as backfillFormSubmissions, i as cleanupRemovedCollections, a3 as collections, a4 as content, a5 as contentVersions, j as createContentFromSubmission, k as deriveCollectionSchemaFromFormio, l as deriveSubmissionTitle, m as fullCollectionSync, n as getAvailableCollectionNames, o as getLogger, p as getManagedCollections, q as initLogger, a6 as insertCollectionSchema, a7 as insertContentSchema, a8 as insertLogConfigSchema, a9 as insertMediaSchema, aa as insertPluginActivityLogSchema, ab as insertPluginAssetSchema, ac as insertPluginHookSchema, ad as insertPluginRouteSchema, ae as insertPluginSchema, af as insertSystemLogSchema, ag as insertUserSchema, ah as insertWorkflowHistorySchema, r as isCollectionManaged, s as loadCollectionConfig, t as loadCollectionConfigs, ai as logConfig, u as mapFormStatusToContentStatus, aj as media, ak as pluginActivityLog, al as pluginAssets, am as pluginHooks, an as pluginRoutes, ao as plugins, v as registerCollections, ap as selectCollectionSchema, aq as selectContentSchema, ar as selectLogConfigSchema, as as selectMediaSchema, at as selectPluginActivityLogSchema, au as selectPluginAssetSchema, av as selectPluginHookSchema, aw as selectPluginRouteSchema, ax as selectPluginSchema, ay as selectSystemLogSchema, az as selectUserSchema, aA as selectWorkflowHistorySchema, w as syncAllFormCollections, x as syncCollection, y as syncCollections, z as syncFormCollection, aB as systemLogs, aC as users, A as validateCollectionConfig, aD as workflowHistory } from './plugin-bootstrap-DfVerYV4.cjs';
export { AuthManager, Permission, PermissionManager, UserPermissions, bootstrapMiddleware, cacheHeaders, compressionMiddleware, detailedLoggingMiddleware, getActivePlugins, isPluginActive, logActivity, loggingMiddleware, optionalAuth, performanceLoggingMiddleware, requireActivePlugin, requireActivePlugins, requireAnyPermission, requireAuth, requirePermission, requireRole, securityHeaders, securityLoggingMiddleware } from './middleware.cjs';
export { H as HookSystemImpl, a as HookUtils, P as PluginManagerClass, b as PluginRegistryImpl, c as PluginValidatorClass, S as ScopedHookSystemClass } from './plugin-manager-BoM3Q7o7.cjs';
export { ROUTES_INFO, adminApiRoutes, adminCheckboxRoutes, adminCodeExamplesRoutes, adminCollectionsRoutes, adminContentRoutes, adminDashboardRoutes, adminDesignRoutes, adminLogsRoutes, adminMediaRoutes, adminPluginRoutes, adminSettingsRoutes, adminTestimonialsRoutes, adminUsersRoutes, apiContentCrudRoutes, apiMediaRoutes, apiRoutes, apiSystemRoutes, authRoutes } from './routes.cjs';
export { A as AlertData, C as ConfirmationDialogOptions, F as Filter, a as FilterBarData, b as FilterOption, c as FormData, d as FormField, P as PaginationData, T as TableColumn, e as TableData, g as getConfirmationDialogScript, r as renderAlert, f as renderConfirmationDialog, h as renderFilterBar, i as renderForm, j as renderFormField, k as renderPagination, l as renderTable } from './filter-bar.template-DlVYMk-T.cjs';
import { e as FieldType } from './collection-config-B4PG-AaF.cjs';
export { C as CollectionConfig, b as CollectionConfigModule, c as CollectionSchema, d as CollectionSyncResult, F as FieldConfig } from './collection-config-B4PG-AaF.cjs';
export { A as AuthService, C as ContentService, H as HOOKS, a as HookContext, b as HookHandler, c as HookName, d as HookSystem, M as MediaService, P as Plugin, f as PluginAdminPage, g as PluginBuilderOptions, h as PluginComponent, i as PluginConfig, j as PluginContext, k as PluginHook, l as PluginLogger, m as PluginManager, n as PluginMenuItem, o as PluginMiddleware, p as PluginModel, q as PluginRegistry, r as PluginRoutes, s as PluginService, t as PluginStatus, u as PluginValidationResult, v as PluginValidator, S as ScopedHookSystem } from './plugin-DDYetMF-.cjs';
export { P as PluginManifest } from './plugin-manifest-Dpy8wxIB.cjs';
export { F as FilterCondition, a as FilterGroup, b as FilterOperator, Q as QueryFilter, c as QueryFilterBuilder, d as QueryResult, S as SONICJS_VERSION, T as TemplateRenderer, e as buildQuery, f as escapeHtml, g as getCoreVersion, m as metricsTracker, r as renderTemplate, s as sanitizeInput, h as sanitizeObject, t as templateRenderer } from './version-ChpccWQ1.cjs';
import * as drizzle_orm_d1 from 'drizzle-orm/d1';
import { Hono, MiddlewareHandler, Context } from 'hono';
import { z } from 'zod';
import { D1Database as D1Database$1, KVNamespace, R2Bucket } from '@cloudflare/workers-types';
import 'drizzle-zod';
import 'drizzle-orm/sqlite-core';
import 'hono/types';

/**
 * SonicJS Plugin System Types
 *
 * Defines the core interfaces and types for the plugin system
 */

interface Plugin {
    /** Unique plugin identifier */
    name: string;
    /** Plugin version (semantic versioning) */
    version: string;
    /** Human-readable description */
    description?: string;
    /** Plugin author information */
    author?: {
        name: string;
        email?: string;
        url?: string;
    };
    /** Plugin dependencies (other plugins required) */
    dependencies?: string[];
    /** SonicJS version compatibility */
    compatibility?: string;
    /** Plugin license */
    license?: string;
    routes?: PluginRoutes[];
    middleware?: PluginMiddleware[];
    models?: PluginModel[];
    services?: PluginService[];
    adminPages?: PluginAdminPage[];
    adminComponents?: PluginComponent[];
    menuItems?: PluginMenuItem[];
    hooks?: PluginHook[];
    install?: (context: PluginContext) => Promise<void>;
    uninstall?: (context: PluginContext) => Promise<void>;
    activate?: (context: PluginContext) => Promise<void>;
    deactivate?: (context: PluginContext) => Promise<void>;
    configure?: (config: PluginConfig) => Promise<void>;
}
interface PluginContext {
    /** Database instance */
    db: D1Database$1;
    /** Key-value storage */
    kv: KVNamespace;
    /** R2 storage bucket */
    r2?: R2Bucket;
    /** Plugin configuration */
    config: PluginConfig;
    /** Core SonicJS services */
    services: {
        auth: AuthService;
        content: ContentService;
        media: MediaService;
    };
    /** Hook system for inter-plugin communication */
    hooks: HookSystem | ScopedHookSystem;
    /** Logging utilities */
    logger: PluginLogger;
}
interface PluginConfig {
    /** Plugin-specific configuration */
    [key: string]: any;
    /** Whether plugin is enabled */
    enabled: boolean;
    /** Plugin installation timestamp */
    installedAt?: number;
    /** Plugin last update timestamp */
    updatedAt?: number;
}
interface PluginRoutes {
    /** Route path prefix */
    path: string;
    /** Hono route handler */
    handler: Hono;
    /** Route description */
    description?: string;
    /** Whether route requires authentication */
    requiresAuth?: boolean;
    /** Required roles for access */
    roles?: string[];
    /** Route priority (for ordering) */
    priority?: number;
}
interface PluginMiddleware {
    /** Middleware name */
    name: string;
    /** Middleware handler function */
    handler: MiddlewareHandler;
    /** Middleware description */
    description?: string;
    /** Middleware priority (lower = earlier) */
    priority?: number;
    /** Routes to apply middleware to */
    routes?: string[];
    /** Whether to apply globally */
    global?: boolean;
}
interface PluginModel {
    /** Model name */
    name: string;
    /** Database table name */
    tableName: string;
    /** Zod schema for validation */
    schema: z.ZodSchema;
    /** Database migrations */
    migrations: string[];
    /** Model relationships */
    relationships?: ModelRelationship[];
    /** Whether model extends core content */
    extendsContent?: boolean;
}
interface ModelRelationship {
    type: 'oneToOne' | 'oneToMany' | 'manyToMany';
    target: string;
    foreignKey?: string;
    joinTable?: string;
}
interface PluginService {
    /** Service name */
    name: string;
    /** Service implementation */
    implementation: any;
    /** Service description */
    description?: string;
    /** Service dependencies */
    dependencies?: string[];
    /** Whether service is singleton */
    singleton?: boolean;
}
interface PluginAdminPage {
    /** Page path (relative to /admin) */
    path: string;
    /** Page title */
    title: string;
    /** Page component/template */
    component: string;
    /** Page description */
    description?: string;
    /** Required permissions */
    permissions?: string[];
    /** Menu item configuration */
    menuItem?: PluginMenuItem;
    /** Page icon */
    icon?: string;
}
interface PluginComponent {
    /** Component name */
    name: string;
    /** Component template function */
    template: (props: any) => string;
    /** Component description */
    description?: string;
    /** Component props schema */
    propsSchema?: z.ZodSchema;
}
interface PluginMenuItem {
    /** Menu item label */
    label: string;
    /** Menu item path */
    path: string;
    /** Menu item icon */
    icon?: string;
    /** Menu item order */
    order?: number;
    /** Parent menu item */
    parent?: string;
    /** Required permissions */
    permissions?: string[];
    /** Whether item is active */
    active?: boolean;
}
interface PluginHook {
    /** Hook name */
    name: string;
    /** Hook handler function */
    handler: HookHandler;
    /** Hook priority */
    priority?: number;
    /** Hook description */
    description?: string;
}
type HookHandler = (data: any, context: HookContext) => Promise<any>;
interface HookContext {
    /** Plugin that registered the hook */
    plugin: string;
    /** Hook execution context */
    context: PluginContext;
    /** Cancel hook execution */
    cancel?: () => void;
}
interface HookSystem {
    /** Register a hook handler */
    register(hookName: string, handler: HookHandler, priority?: number): void;
    /** Execute all handlers for a hook */
    execute(hookName: string, data: any, context?: any): Promise<any>;
    /** Remove a hook handler */
    unregister(hookName: string, handler: HookHandler): void;
    /** Get all registered hooks */
    getHooks(hookName: string): PluginHook[];
    /** Create a scoped hook system (optional) */
    createScope?(pluginName: string): ScopedHookSystem;
}
interface ScopedHookSystem {
    /** Register a hook handler */
    register(hookName: string, handler: HookHandler, priority?: number): void;
    /** Execute all handlers for a hook */
    execute(hookName: string, data: any, context?: any): Promise<any>;
    /** Remove a hook handler */
    unregister(hookName: string, handler: HookHandler): void;
    /** Remove all hooks for this scope */
    unregisterAll(): void;
}
interface AuthService {
    /** Generate JWT token for a user */
    generateToken(userId: string, email: string, role: string): Promise<string>;
    /** Verify and decode JWT token */
    verifyToken(token: string): Promise<any>;
    /** Set authentication cookie (useful for alternative auth methods) */
    setAuthCookie(context: Context, token: string, options?: {
        maxAge?: number;
        secure?: boolean;
        httpOnly?: boolean;
        sameSite?: 'Strict' | 'Lax' | 'None';
    }): void;
    /** Hash password */
    hashPassword(password: string): Promise<string>;
    /** Verify password against hash */
    verifyPassword(password: string, hash: string): Promise<boolean>;
}
interface AuthService {
    /** Verify user permissions */
    hasPermission(userId: string, permission: string): Promise<boolean>;
    /** Get current user */
    getCurrentUser(context: Context): Promise<any>;
    /** Create authentication middleware */
    createMiddleware(options?: any): MiddlewareHandler;
}
interface ContentService {
    /** Get content by ID */
    getById(id: string): Promise<any>;
    /** Create new content */
    create(data: any): Promise<any>;
    /** Update content */
    update(id: string, data: any): Promise<any>;
    /** Delete content */
    delete(id: string): Promise<void>;
    /** Search content */
    search(query: string, options?: any): Promise<any[]>;
}
interface MediaService {
    /** Upload file */
    upload(file: File, options?: any): Promise<any>;
    /** Get media by ID */
    getById(id: string): Promise<any>;
    /** Delete media */
    delete(id: string): Promise<void>;
    /** Transform image */
    transform(id: string, options: any): Promise<string>;
}
interface PluginLogger {
    debug(message: string, data?: any): void;
    info(message: string, data?: any): void;
    warn(message: string, data?: any): void;
    error(message: string, error?: Error, data?: any): void;
}
interface PluginBuilderOptions {
    name: string;
    version: string;
    description?: string;
    author?: Plugin['author'];
    dependencies?: string[];
}

declare function createDb(d1: D1Database): drizzle_orm_d1.DrizzleD1Database<typeof schema> & {
    $client: D1Database;
};

/**
 * Plugin Builder SDK
 *
 * Provides a fluent API for building SonicJS plugins
 *
 * @packageDocumentation
 */

/**
 * Fluent builder for creating SonicJS plugins.
 *
 * @beta This API is in beta and may change in future releases.
 *
 * @example
 * ```typescript
 * import { PluginBuilder } from '@sonicjs-cms/core'
 *
 * const plugin = PluginBuilder.create({
 *   name: 'my-plugin',
 *   version: '1.0.0',
 *   description: 'My custom plugin'
 * })
 *   .addRoute('/api/my-plugin', routes)
 *   .addHook('content:save', handler)
 *   .lifecycle({ activate: async () => console.log('Activated!') })
 *   .build()
 * ```
 */
declare class PluginBuilder {
    private plugin;
    constructor(options: PluginBuilderOptions);
    /**
     * Create a new plugin builder
     */
    static create(options: PluginBuilderOptions): PluginBuilder;
    /**
     * Add metadata to the plugin
     */
    metadata(metadata: {
        description?: string;
        author?: Plugin['author'];
        license?: string;
        compatibility?: string;
        dependencies?: string[];
    }): PluginBuilder;
    /**
     * Add routes to plugin
     */
    addRoutes(routes: PluginRoutes[]): PluginBuilder;
    /**
     * Add a single route to plugin
     */
    addRoute(path: string, handler: Hono, options?: {
        description?: string;
        requiresAuth?: boolean;
        roles?: string[];
        priority?: number;
    }): PluginBuilder;
    /**
     * Add middleware to plugin
     */
    addMiddleware(middleware: PluginMiddleware[]): PluginBuilder;
    /**
     * Add a single middleware to plugin
     */
    addSingleMiddleware(name: string, handler: any, options?: {
        description?: string;
        priority?: number;
        routes?: string[];
        global?: boolean;
    }): PluginBuilder;
    /**
     * Add models to plugin
     */
    addModels(models: PluginModel[]): PluginBuilder;
    /**
     * Add a single model to plugin
     */
    addModel(name: string, options: {
        tableName: string;
        schema: z.ZodSchema;
        migrations: string[];
        relationships?: PluginModel['relationships'];
        extendsContent?: boolean;
    }): PluginBuilder;
    /**
     * Add services to plugin
     */
    addServices(services: PluginService[]): PluginBuilder;
    /**
     * Add a single service to plugin
     */
    addService(name: string, implementation: any, options?: {
        description?: string;
        dependencies?: string[];
        singleton?: boolean;
    }): PluginBuilder;
    /**
     * Add admin pages to plugin
     */
    addAdminPages(pages: PluginAdminPage[]): PluginBuilder;
    /**
     * Add a single admin page to plugin
     */
    addAdminPage(path: string, title: string, component: string, options?: {
        description?: string;
        permissions?: string[];
        icon?: string;
        menuItem?: PluginMenuItem;
    }): PluginBuilder;
    /**
     * Add admin components to plugin
     */
    addComponents(components: PluginComponent[]): PluginBuilder;
    /**
     * Add a single admin component to plugin
     */
    addComponent(name: string, template: (props: any) => string, options?: {
        description?: string;
        propsSchema?: z.ZodSchema;
    }): PluginBuilder;
    /**
     * Add menu items to plugin
     */
    addMenuItems(items: PluginMenuItem[]): PluginBuilder;
    /**
     * Add a single menu item to plugin
     */
    addMenuItem(label: string, path: string, options?: {
        icon?: string;
        order?: number;
        parent?: string;
        permissions?: string[];
    }): PluginBuilder;
    /**
     * Add hooks to plugin
     */
    addHooks(hooks: PluginHook[]): PluginBuilder;
    /**
     * Add a single hook to plugin
     */
    addHook(name: string, handler: any, options?: {
        priority?: number;
        description?: string;
    }): PluginBuilder;
    /**
     * Add lifecycle hooks
     */
    lifecycle(hooks: {
        install?: Plugin['install'];
        uninstall?: Plugin['uninstall'];
        activate?: Plugin['activate'];
        deactivate?: Plugin['deactivate'];
        configure?: Plugin['configure'];
    }): PluginBuilder;
    /**
     * Build the plugin
     */
    build(): Plugin;
}
/**
 * Helper functions for common plugin patterns.
 *
 * @beta This API is in beta and may change in future releases.
 */
declare class PluginHelpers {
    /**
     * Create a REST API route for a model.
     *
     * @experimental This method returns placeholder routes. Full implementation coming soon.
     */
    static createModelAPI(modelName: string, options?: {
        basePath?: string;
        permissions?: {
            read?: string[];
            write?: string[];
            delete?: string[];
        };
    }): Hono;
    /**
     * Create an admin CRUD interface for a model.
     *
     * @experimental This method generates basic admin page structures. Full implementation coming soon.
     */
    static createAdminInterface(modelName: string, options?: {
        icon?: string;
        permissions?: string[];
        fields?: Array<{
            name: string;
            type: string;
            label: string;
            required?: boolean;
        }>;
    }): {
        pages: PluginAdminPage[];
        menuItems: PluginMenuItem[];
    };
    /**
     * Create a database migration for a model
     */
    static createMigration(tableName: string, fields: Array<{
        name: string;
        type: 'TEXT' | 'INTEGER' | 'REAL' | 'BLOB';
        nullable?: boolean;
        primaryKey?: boolean;
        unique?: boolean;
        defaultValue?: string;
    }>): string;
    /**
     * Create a Zod schema for a model
     */
    static createSchema(fields: Array<{
        name: string;
        type: 'string' | 'number' | 'boolean' | 'date' | 'array' | 'object';
        optional?: boolean;
        required?: boolean;
        validation?: any;
        items?: any;
        properties?: Record<string, any>;
    }>): z.ZodSchema;
}

/**
 * OAuth Providers Plugin
 *
 * OAuth2/OIDC social login support for SonicJS.
 * Phase 1: Core OAuth2 authorization code flow with GitHub and Google providers.
 *
 * Routes:
 *   GET  /auth/oauth/:provider          → Redirect to provider authorization
 *   GET  /auth/oauth/:provider/callback → Handle OAuth callback
 *   POST /auth/oauth/link               → Link OAuth provider to logged-in account
 *   POST /auth/oauth/unlink             → Unlink OAuth provider from account
 *   GET  /auth/oauth/accounts           → List linked OAuth accounts for current user
 */

declare function createOAuthProvidersPlugin(): Plugin;
declare const oauthProvidersPlugin: Plugin;

/**
 * OAuth Service
 * Handles OAuth2 authorization code flow, token exchange, and user info fetching.
 * Provider-agnostic — each provider is a simple config object.
 */

interface OAuthProviderConfig {
    id: string;
    name: string;
    authorizeUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
    scopes: string[];
    /** Map provider profile JSON to a normalized user profile */
    mapProfile: (profile: Record<string, any>) => OAuthUserProfile;
}
interface OAuthUserProfile {
    providerAccountId: string;
    email: string;
    name: string;
    avatar?: string;
}
declare const BUILT_IN_PROVIDERS: Record<string, OAuthProviderConfig>;
interface OAuthAccount {
    id: string;
    user_id: string;
    provider: string;
    provider_account_id: string;
    access_token: string | null;
    refresh_token: string | null;
    token_expires_at: number | null;
    profile_data: string | null;
    created_at: number;
    updated_at: number;
}
declare class OAuthService {
    private db;
    constructor(db: D1Database$1);
    /**
     * Build the authorization redirect URL for a provider.
     */
    buildAuthorizeUrl(provider: OAuthProviderConfig, clientId: string, redirectUri: string, state: string): string;
    /**
     * Exchange authorization code for tokens using native fetch.
     */
    exchangeCode(provider: OAuthProviderConfig, clientId: string, clientSecret: string, code: string, redirectUri: string): Promise<{
        access_token: string;
        refresh_token?: string;
        expires_in?: number;
    }>;
    /**
     * Fetch user profile from the provider's userinfo endpoint.
     */
    fetchUserProfile(provider: OAuthProviderConfig, accessToken: string): Promise<OAuthUserProfile>;
    /**
     * Find an existing OAuth account link.
     */
    findOAuthAccount(provider: string, providerAccountId: string): Promise<OAuthAccount | null>;
    /**
     * Find all OAuth accounts for a user.
     */
    findUserOAuthAccounts(userId: string): Promise<OAuthAccount[]>;
    /**
     * Create a new OAuth account link.
     */
    createOAuthAccount(params: {
        userId: string;
        provider: string;
        providerAccountId: string;
        accessToken: string;
        refreshToken?: string;
        tokenExpiresAt?: number;
        profileData?: string;
    }): Promise<OAuthAccount>;
    /**
     * Update tokens for an existing OAuth account.
     */
    updateOAuthTokens(id: string, accessToken: string, refreshToken?: string, tokenExpiresAt?: number): Promise<void>;
    /**
     * Unlink an OAuth account from a user (only if they have another auth method).
     */
    unlinkOAuthAccount(userId: string, provider: string): Promise<boolean>;
    /**
     * Find a user by email.
     */
    findUserByEmail(email: string): Promise<{
        id: string;
        email: string;
        role: string;
        is_active: number;
        first_name: string;
        last_name: string;
    } | null>;
    /**
     * Create a new user from an OAuth profile.
     */
    createUserFromOAuth(profile: OAuthUserProfile): Promise<string>;
    /**
     * Generate a cryptographically random state parameter for CSRF protection.
     */
    generateState(): string;
}

/**
 * User Profile Config Registry
 *
 * Global singleton storing developer-defined custom profile field definitions.
 * Set once at app boot via defineUserProfile(), queried by routes and templates.
 */

interface ProfileFieldDefinition {
    name: string;
    label: string;
    type: FieldType;
    options?: string[];
    default?: any;
    required?: boolean;
    placeholder?: string;
    helpText?: string;
    hidden?: boolean;
    fields?: ProfileFieldDefinition[];
    validation?: {
        min?: number;
        max?: number;
        pattern?: string;
    };
}
interface UserProfileConfig {
    fields: ProfileFieldDefinition[];
    registrationFields?: string[];
}
declare function defineUserProfile(config: UserProfileConfig): void;
declare function getUserProfileConfig(): UserProfileConfig | null;

/**
 * User Profiles Plugin
 *
 * Configurable custom profile fields for users.
 * Developers call defineUserProfile() at app boot to declare custom fields
 * that are stored as JSON in user_profiles.data and rendered in the admin UI.
 *
 * API Routes:
 *   GET  /api/user-profiles/schema     → Public field definitions
 *   GET  /api/user-profiles/:userId    → Get custom data for a user (auth required)
 *   PUT  /api/user-profiles/:userId    → Update custom data for a user (auth required)
 */

declare function createUserProfilesPlugin(): Plugin;
declare const userProfilesPlugin: Plugin;

/**
 * @sonicjs/core - Main Entry Point
 *
 * Core framework for SonicJS headless CMS
 * Built for Cloudflare's edge platform with TypeScript
 *
 * Phase 2 Migration Status:
 * - Week 1: Types, Utils, Database (COMPLETED ✓)
 * - Week 2: Services, Middleware, Plugins (COMPLETED ✓)
 * - Week 3: Routes, Templates (COMPLETED ✓)
 * - Week 4: Integration & Testing (COMPLETED ✓)
 *
 * Test Coverage:
 * - Utilities: 48 tests (sanitize, query-filter, metrics)
 * - Middleware: 51 tests (auth, logging, security, performance)
 * - Total: 99 tests passing
 */

declare const VERSION: string;

export { BUILT_IN_PROVIDERS, FieldType, OAuthService, PluginBuilder, PluginHelpers, type ProfileFieldDefinition, type UserProfileConfig, VERSION, createDb, createOAuthProvidersPlugin, createUserProfilesPlugin, defineUserProfile, getUserProfileConfig, oauthProvidersPlugin, userProfilesPlugin };
