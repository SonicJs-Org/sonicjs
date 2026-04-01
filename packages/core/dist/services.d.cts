export { b as CorePlugin, L as LogCategory, e as LogEntry, f as LogFilter, g as LogLevel, h as Logger, i as Migration, j as MigrationService, k as MigrationStatus, z as PluginBootstrapService, B as PluginService, E as cleanupRemovedCollections, I as fullCollectionSync, J as getAvailableCollectionNames, K as getLogger, O as getManagedCollections, Q as initLogger, a4 as isCollectionManaged, a5 as loadCollectionConfig, a6 as loadCollectionConfigs, ae as registerCollections, ar as syncCollection, as as syncCollections, av as validateCollectionConfig } from './plugin-bootstrap-Dcu8i6h1.cjs';
import { T as TelemetryConfig, b as TelemetryIdentity, a as TelemetryEvent, c as TelemetryProperties } from './telemetry-B9vIV4wh.cjs';
import './collection-config-DckWhkdL.cjs';
import '@cloudflare/workers-types';
import 'drizzle-zod';
import 'drizzle-orm/sqlite-core';

/**
 * Simple Cache Service
 *
 * Provides basic caching functionality for the core package
 * Can be extended with KV or other storage backends
 */
interface CacheConfig {
    ttl: number;
    keyPrefix: string;
}
declare class CacheService {
    private config;
    private memoryCache;
    constructor(config: CacheConfig);
    /**
     * Generate cache key with prefix
     */
    generateKey(type: string, identifier?: string): string;
    /**
     * Get value from cache
     */
    get<T>(key: string): Promise<T | null>;
    /**
     * Get value from cache with source information
     */
    getWithSource<T>(key: string): Promise<{
        hit: boolean;
        data: T | null;
        source: string;
        ttl?: number;
    }>;
    /**
     * Set value in cache
     */
    set(key: string, value: any, ttl?: number): Promise<void>;
    /**
     * Delete specific key from cache
     */
    delete(key: string): Promise<void>;
    /**
     * Invalidate cache keys matching a pattern
     * For memory cache, we do simple string matching
     */
    invalidate(pattern: string): Promise<void>;
    /**
     * Clear all cache
     */
    clear(): Promise<void>;
    /**
     * Get value from cache or set it using a callback
     */
    getOrSet<T>(key: string, callback: () => Promise<T>, ttl?: number): Promise<T>;
}
/**
 * Cache configurations for different data types
 */
declare const CACHE_CONFIGS: {
    api: {
        ttl: number;
        keyPrefix: string;
    };
    user: {
        ttl: number;
        keyPrefix: string;
    };
    content: {
        ttl: number;
        keyPrefix: string;
    };
    collection: {
        ttl: number;
        keyPrefix: string;
    };
};
/**
 * Get cache service instance for a config
 */
declare function getCacheService(config: CacheConfig): CacheService;

interface Setting {
    id: string;
    category: string;
    key: string;
    value: string;
    created_at: number;
    updated_at: number;
}
interface GeneralSettings {
    siteName: string;
    siteDescription: string;
    adminEmail: string;
    timezone: string;
    language: string;
    maintenanceMode: boolean;
}
declare class SettingsService {
    private db;
    constructor(db: D1Database);
    /**
     * Get a setting value by category and key
     */
    getSetting(category: string, key: string): Promise<any | null>;
    /**
     * Get all settings for a category
     */
    getCategorySettings(category: string): Promise<Record<string, any>>;
    /**
     * Set a setting value
     */
    setSetting(category: string, key: string, value: any): Promise<boolean>;
    /**
     * Set multiple settings at once
     */
    setMultipleSettings(category: string, settings: Record<string, any>): Promise<boolean>;
    /**
     * Get general settings with defaults
     */
    getGeneralSettings(userEmail?: string): Promise<GeneralSettings>;
    /**
     * Save general settings
     */
    saveGeneralSettings(settings: Partial<GeneralSettings>): Promise<boolean>;
}

/**
 * Telemetry Service
 *
 * Privacy-first telemetry service using custom SonicJS stats endpoint
 * - No PII collection
 * - Opt-out by default
 * - Silent failures (never blocks app)
 */

/**
 * TelemetryService class
 *
 * Handles all telemetry tracking in a privacy-conscious way
 */
declare class TelemetryService {
    private config;
    private identity;
    private enabled;
    private eventQueue;
    private isInitialized;
    constructor(config?: Partial<TelemetryConfig>);
    /**
     * Initialize the telemetry service
     */
    initialize(identity: TelemetryIdentity): Promise<void>;
    /**
     * Track a telemetry event
     */
    track(event: TelemetryEvent, properties?: TelemetryProperties): Promise<void>;
    /**
     * Track installation started
     */
    trackInstallationStarted(properties?: TelemetryProperties): Promise<void>;
    /**
     * Track installation completed
     */
    trackInstallationCompleted(properties?: TelemetryProperties): Promise<void>;
    /**
     * Track installation failed
     */
    trackInstallationFailed(error: Error | string, properties?: TelemetryProperties): Promise<void>;
    /**
     * Track dev server started
     */
    trackDevServerStarted(properties?: TelemetryProperties): Promise<void>;
    /**
     * Track page view in admin UI
     */
    trackPageView(route: string, properties?: TelemetryProperties): Promise<void>;
    /**
     * Track error (sanitized)
     */
    trackError(error: Error | string, properties?: TelemetryProperties): Promise<void>;
    /**
     * Track plugin activation
     */
    trackPluginActivated(properties?: TelemetryProperties): Promise<void>;
    /**
     * Track migration run
     */
    trackMigrationRun(properties?: TelemetryProperties): Promise<void>;
    /**
     * Flush queued events
     */
    private flushQueue;
    /**
     * Sanitize properties to ensure no PII
     */
    private sanitizeProperties;
    /**
     * Get SonicJS version
     */
    private getVersion;
    /**
     * Shutdown the telemetry service (no-op for fetch-based telemetry)
     */
    shutdown(): Promise<void>;
    /**
     * Enable telemetry
     */
    enable(): void;
    /**
     * Disable telemetry
     */
    disable(): void;
    /**
     * Check if telemetry is enabled
     */
    isEnabled(): boolean;
}
/**
 * Get the telemetry service instance
 */
declare function getTelemetryService(config?: Partial<TelemetryConfig>): TelemetryService;
/**
 * Initialize telemetry service
 */
declare function initTelemetry(identity: TelemetryIdentity, config?: Partial<TelemetryConfig>): Promise<TelemetryService>;
/**
 * Create a new installation identity
 */
declare function createInstallationIdentity(projectName?: string): TelemetryIdentity;

/**
 * Route Metadata Service
 *
 * Auto-discovers API routes using Hono's inspectRoutes() and enriches them
 * with metadata from a static registry. Routes without metadata still appear
 * as "auto-discovered" — nothing is ever invisible.
 */
interface RouteMetadata {
    method: string;
    path: string;
    description: string;
    authentication: boolean | 'unknown';
    category: string;
    documented: boolean;
}
interface CategoryInfo {
    title: string;
    description: string;
    icon: string;
}
declare function setAppInstance(app: any): void;
declare function getAppInstance(): any;
declare const CATEGORY_INFO: Record<string, CategoryInfo>;
declare function buildRouteList(app: any): RouteMetadata[];

export { CACHE_CONFIGS, CATEGORY_INFO, type CacheConfig, CacheService, type GeneralSettings, type RouteMetadata, type Setting, SettingsService, TelemetryService, buildRouteList, createInstallationIdentity, getAppInstance, getCacheService, getTelemetryService, initTelemetry, setAppInstance };
