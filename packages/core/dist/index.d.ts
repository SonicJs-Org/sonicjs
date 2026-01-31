export { B as Bindings, b as SonicJSApp, S as SonicJSConfig, V as Variables, c as createSonicJSApp, s as setupCoreMiddleware, a as setupCoreRoutes } from './app-CYEm1ytG.js';
import { t as schema } from './plugin-bootstrap-BCubdas2.js';
export { ab as Collection, ad as Content, C as CorePlugin, aj as DbPlugin, al as DbPluginHook, n as LogCategory, av as LogConfig, o as LogEntry, p as LogFilter, m as LogLevel, L as Logger, af as Media, e as Migration, M as MigrationService, h as MigrationStatus, ac as NewCollection, ae as NewContent, aw as NewLogConfig, ag as NewMedia, ak as NewPlugin, as as NewPluginActivityLog, aq as NewPluginAsset, am as NewPluginHook, ao as NewPluginRoute, au as NewSystemLog, aa as NewUser, ai as NewWorkflowHistory, ar as PluginActivityLog, ap as PluginAsset, q as PluginBootstrapService, an as PluginRoute, P as PluginServiceClass, at as SystemLog, a9 as User, ah as WorkflowHistory, A as apiTokens, d as cleanupRemovedCollections, w as collections, x as content, y as contentVersions, f as fullCollectionSync, g as getAvailableCollectionNames, j as getLogger, c as getManagedCollections, k as initLogger, O as insertCollectionSchema, R as insertContentSchema, a7 as insertLogConfigSchema, T as insertMediaSchema, a3 as insertPluginActivityLogSchema, a1 as insertPluginAssetSchema, Z as insertPluginHookSchema, $ as insertPluginRouteSchema, X as insertPluginSchema, a5 as insertSystemLogSchema, K as insertUserSchema, V as insertWorkflowHistorySchema, i as isCollectionManaged, a as loadCollectionConfig, l as loadCollectionConfigs, J as logConfig, z as media, H as pluginActivityLog, G as pluginAssets, E as pluginHooks, F as pluginRoutes, D as plugins, r as registerCollections, Q as selectCollectionSchema, S as selectContentSchema, a8 as selectLogConfigSchema, U as selectMediaSchema, a4 as selectPluginActivityLogSchema, a2 as selectPluginAssetSchema, _ as selectPluginHookSchema, a0 as selectPluginRouteSchema, Y as selectPluginSchema, a6 as selectSystemLogSchema, N as selectUserSchema, W as selectWorkflowHistorySchema, b as syncCollection, s as syncCollections, I as systemLogs, u as users, v as validateCollectionConfig, B as workflowHistory } from './plugin-bootstrap-BCubdas2.js';
export { AuthManager, Permission, PermissionManager, UserPermissions, bootstrapMiddleware, cacheHeaders, compressionMiddleware, detailedLoggingMiddleware, getActivePlugins, isPluginActive, logActivity, loggingMiddleware, optionalAuth, performanceLoggingMiddleware, requireActivePlugin, requireActivePlugins, requireAnyPermission, requireAuth, requirePermission, requireRole, securityHeaders, securityLoggingMiddleware } from './middleware.js';
export { H as HookSystemImpl, a as HookUtils, b as PluginManagerClass, P as PluginRegistryImpl, c as PluginValidatorClass, S as ScopedHookSystemClass } from './plugin-manager-Baa6xXqB.js';
export { ROUTES_INFO, adminApiRoutes, adminCheckboxRoutes, adminCodeExamplesRoutes, adminCollectionsRoutes, adminContentRoutes, adminDashboardRoutes, adminDesignRoutes, adminLogsRoutes, adminMediaRoutes, adminPluginRoutes, adminSettingsRoutes, adminTestimonialsRoutes, adminUsersRoutes, apiContentCrudRoutes, apiMediaRoutes, apiRoutes, apiSystemRoutes, authRoutes } from './routes.js';
export { A as AlertData, C as ConfirmationDialogOptions, k as Filter, j as FilterBarData, l as FilterOption, h as FormData, F as FormField, P as PaginationData, T as TableColumn, i as TableData, g as getConfirmationDialogScript, d as renderAlert, e as renderConfirmationDialog, f as renderFilterBar, r as renderForm, a as renderFormField, c as renderPagination, b as renderTable } from './filter-bar.template-By4jeiw_.js';
export { c as CollectionConfig, d as CollectionConfigModule, C as CollectionSchema, e as CollectionSyncResult, a as FieldConfig, F as FieldType } from './collection-config-BF95LgQb.js';
export { A as AuthService, C as ContentService, v as HOOKS, k as HookContext, H as HookHandler, u as HookName, l as HookSystem, p as MediaService, P as Plugin, g as PluginAdminPage, r as PluginBuilderOptions, h as PluginComponent, b as PluginConfig, a as PluginContext, j as PluginHook, q as PluginLogger, n as PluginManager, i as PluginMenuItem, d as PluginMiddleware, e as PluginModel, m as PluginRegistry, c as PluginRoutes, f as PluginService, o as PluginStatus, t as PluginValidationResult, s as PluginValidator, S as ScopedHookSystem } from './plugin-zvZpaiP5.js';
export { P as PluginManifest } from './plugin-manifest-Dpy8wxIB.js';
export { c as FilterCondition, d as FilterGroup, F as FilterOperator, f as QueryFilter, Q as QueryFilterBuilder, h as QueryResult, S as SONICJS_VERSION, T as TemplateRenderer, b as buildQuery, e as escapeHtml, g as getCoreVersion, m as metricsTracker, r as renderTemplate, s as sanitizeInput, a as sanitizeObject, t as templateRenderer } from './version-vktVAxhe.js';
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

export { PluginBuilder, PluginHelpers, VERSION, createDb };
