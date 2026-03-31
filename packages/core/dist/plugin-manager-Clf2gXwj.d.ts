import { d as HookSystem, b as HookHandler, k as PluginHook, v as PluginValidator$1, P as Plugin, u as PluginValidationResult, q as PluginRegistry, i as PluginConfig, t as PluginStatus, m as PluginManager$1, j as PluginContext } from './plugin-0Xogrln-.js';
import { Hono } from 'hono';

/**
 * Hook System Implementation
 *
 * Provides event-driven extensibility for plugins
 */

declare class HookSystemImpl implements HookSystem {
    private hooks;
    private executing;
    /**
     * Register a hook handler
     */
    register(hookName: string, handler: HookHandler, priority?: number): void;
    /**
     * Execute all handlers for a hook
     */
    execute(hookName: string, data: any, context?: any): Promise<any>;
    /**
     * Remove a hook handler
     */
    unregister(hookName: string, handler: HookHandler): void;
    /**
     * Get all registered hooks for a name
     */
    getHooks(hookName: string): PluginHook[];
    /**
     * Get all registered hook names
     */
    getHookNames(): string[];
    /**
     * Get hook statistics
     */
    getStats(): {
        hookName: string;
        handlerCount: number;
    }[];
    /**
     * Clear all hooks (useful for testing)
     */
    clear(): void;
    /**
     * Create a scoped hook system for a plugin
     */
    createScope(_pluginName: string): ScopedHookSystem;
}
/**
 * Scoped hook system for individual plugins
 */
declare class ScopedHookSystem {
    private parent;
    private registeredHooks;
    constructor(parent: HookSystemImpl);
    /**
     * Register a hook (scoped to this plugin)
     */
    register(hookName: string, handler: HookHandler, priority?: number): void;
    /**
     * Execute a hook
     */
    execute(hookName: string, data: any, context?: any): Promise<any>;
    /**
     * Unregister a specific hook
     */
    unregister(hookName: string, handler: HookHandler): void;
    /**
     * Unregister all hooks for this plugin
     */
    unregisterAll(): void;
    /**
     * Get hooks registered by this plugin
     */
    getRegisteredHooks(): {
        hookName: string;
        handler: HookHandler;
    }[];
}
/**
 * Hook utilities
 */
declare class HookUtils {
    /**
     * Create a hook name with namespace
     */
    static createHookName(namespace: string, event: string): string;
    /**
     * Parse a hook name to extract namespace and event
     */
    static parseHookName(hookName: string): {
        namespace: string;
        event: string;
    };
    /**
     * Create a middleware that executes hooks
     */
    static createHookMiddleware(hookSystem: HookSystem, beforeHook?: string, afterHook?: string): (c: any, next: any) => Promise<void>;
    /**
     * Create a debounced hook handler
     */
    static debounce(handler: HookHandler, delay: number): HookHandler;
    /**
     * Create a throttled hook handler
     */
    static throttle(handler: HookHandler, limit: number): HookHandler;
}

/**
 * Plugin Validator
 *
 * Validates plugin definitions, dependencies, and compatibility
 */

declare class PluginValidator implements PluginValidator$1 {
    private static readonly RESERVED_NAMES;
    private static readonly RESERVED_PATHS;
    /**
     * Validate plugin definition
     */
    validate(plugin: Plugin): PluginValidationResult;
    /**
     * Validate plugin dependencies
     */
    validateDependencies(plugin: Plugin, registry: PluginRegistry): PluginValidationResult;
    /**
     * Validate plugin compatibility with SonicJS version
     */
    validateCompatibility(plugin: Plugin, sonicVersion: string): PluginValidationResult;
    /**
     * Check if two version ranges are compatible
     */
    private isCompatible;
    /**
     * Validate plugin security constraints
     */
    validateSecurity(plugin: Plugin): PluginValidationResult;
}

/**
 * Plugin Registry Implementation
 *
 * Manages plugin registration, activation, and lifecycle
 */

declare class PluginRegistryImpl implements PluginRegistry {
    private plugins;
    private configs;
    private statuses;
    private validator;
    constructor(validator?: PluginValidator);
    /**
     * Get plugin by name
     */
    get(name: string): Plugin | undefined;
    /**
     * Get all registered plugins
     */
    getAll(): Plugin[];
    /**
     * Get active plugins
     */
    getActive(): Plugin[];
    /**
     * Register a plugin
     */
    register(plugin: Plugin): Promise<void>;
    /**
     * Unregister a plugin
     */
    unregister(name: string): Promise<void>;
    /**
     * Check if plugin is registered
     */
    has(name: string): boolean;
    /**
     * Activate a plugin
     */
    activate(name: string): Promise<void>;
    /**
     * Deactivate a plugin
     */
    deactivate(name: string): Promise<void>;
    /**
     * Get plugin configuration
     */
    getConfig(name: string): PluginConfig | undefined;
    /**
     * Set plugin configuration
     */
    setConfig(name: string, config: PluginConfig): void;
    /**
     * Get plugin status
     */
    getStatus(name: string): PluginStatus | undefined;
    /**
     * Get all plugin statuses
     */
    getAllStatuses(): Map<string, PluginStatus>;
    /**
     * Update plugin status
     */
    private updateStatus;
    /**
     * Get plugins that depend on the specified plugin
     */
    private getDependents;
    /**
     * Get dependency graph
     */
    getDependencyGraph(): Map<string, string[]>;
    /**
     * Resolve plugin load order based on dependencies
     */
    resolveLoadOrder(): string[];
    /**
     * Export plugin configuration
     */
    exportConfig(): {
        plugins: PluginConfig[];
    };
    /**
     * Import plugin configuration
     */
    importConfig(config: {
        plugins: PluginConfig[];
    }): void;
    /**
     * Clear all plugins (useful for testing)
     */
    clear(): void;
    /**
     * Get registry statistics
     */
    getStats(): {
        total: number;
        active: number;
        inactive: number;
        withErrors: number;
    };
}

/**
 * Plugin Manager
 *
 * Central orchestrator for the plugin system
 */

declare class PluginManager implements PluginManager$1 {
    readonly registry: PluginRegistry;
    readonly hooks: HookSystem;
    private validator;
    private context?;
    private scopedHooks;
    private pluginRoutes;
    constructor();
    /**
     * Initialize plugin system
     */
    initialize(context: PluginContext): Promise<void>;
    /**
     * Load plugins from configuration
     */
    loadPlugins(configs: PluginConfig[]): Promise<void>;
    /**
     * Install a plugin
     */
    install(plugin: Plugin, config?: PluginConfig): Promise<void>;
    /**
     * Uninstall a plugin
     */
    uninstall(name: string): Promise<void>;
    /**
     * Get plugin status
     */
    getStatus(name: string): PluginStatus;
    /**
     * Get all plugin statuses
     */
    getAllStatuses(): PluginStatus[];
    /**
     * Register plugin extensions (routes, middleware, etc.)
     */
    private registerPluginExtensions;
    /**
     * Unregister plugin extensions
     */
    private unregisterPluginExtensions;
    /**
     * Update plugin status
     */
    private updatePluginStatus;
    /**
     * Create a logger for a plugin
     */
    private createLogger;
    /**
     * Get plugin routes for mounting in main app
     */
    getPluginRoutes(): Map<string, Hono>;
    /**
     * Get plugin middleware for main app
     */
    getPluginMiddleware(): Array<{
        name: string;
        handler: any;
        priority: number;
        global: boolean;
    }>;
    /**
     * Execute shutdown procedures
     */
    shutdown(): Promise<void>;
    /**
     * Get plugin system statistics
     */
    getStats(): {
        registry: ReturnType<PluginRegistryImpl['getStats']>;
        hooks: Array<{
            hookName: string;
            handlerCount: number;
        }>;
        routes: number;
        middleware: number;
    };
}

export { HookSystemImpl as H, PluginManager as P, ScopedHookSystem as S, HookUtils as a, PluginRegistryImpl as b, PluginValidator as c };
