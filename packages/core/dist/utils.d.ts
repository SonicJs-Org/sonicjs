export { F as FilterCondition, a as FilterGroup, b as FilterOperator, Q as QueryFilter, c as QueryFilterBuilder, d as QueryResult, S as SONICJS_VERSION, T as TemplateRenderer, e as buildQuery, f as escapeHtml, g as getCoreVersion, m as metricsTracker, r as renderTemplate, s as sanitizeInput, h as sanitizeObject, t as templateRenderer } from './version-ChpccWQ1.js';
import { T as TelemetryConfig } from './telemetry-B9vIV4wh.js';
import { a as BlockDefinitions } from './collection-config-DckWhkdL.js';

/**
 * Slug generation utilities for creating URL-friendly slugs
 */
/**
 * Generate URL-friendly slug from text
 *
 * Features:
 * - Converts to lowercase
 * - Handles accented characters (NFD normalization)
 * - Removes diacritics
 * - Keeps only alphanumeric, spaces, underscores, and hyphens
 * - Replaces spaces with hyphens
 * - Collapses multiple hyphens/underscores
 * - Trims leading/trailing hyphens/underscores
 * - Limits length to 100 characters
 *
 * @param text - Text to slugify
 * @returns URL-safe slug
 *
 * @example
 * generateSlug('Hello World!') // 'hello-world'
 * generateSlug('Café París 2024') // 'cafe-paris-2024'
 * generateSlug('Multiple   Spaces') // 'multiple-spaces'
 */
declare function generateSlug(text: string): string;

/**
 * Telemetry ID Utilities
 *
 * Generates and manages anonymous installation IDs
 */
/**
 * Generate a new anonymous installation ID
 * Uses globalThis.crypto for Cloudflare Workers compatibility
 */
declare function generateInstallationId(): string;
/**
 * Generate a project-specific ID from project name
 * Uses a simple hash to anonymize while maintaining consistency
 */
declare function generateProjectId(projectName: string): string;
/**
 * Sanitize error messages to remove any potential PII
 */
declare function sanitizeErrorMessage(error: Error | string): string;
/**
 * Sanitize route to remove any user-specific data
 */
declare function sanitizeRoute(route: string): string;

/**
 * Telemetry Configuration Utilities
 *
 * Manages telemetry settings and opt-out mechanisms
 */

/**
 * Get default telemetry configuration
 * Uses lazy evaluation to avoid accessing process.env at module load time
 */
declare function getDefaultTelemetryConfig(): TelemetryConfig;
/**
 * Check if telemetry is enabled via environment variables
 */
declare function isTelemetryEnabled(): boolean;
/**
 * Get telemetry configuration from environment
 */
declare function getTelemetryConfig(): TelemetryConfig;
/**
 * Check if telemetry should be skipped for this event
 * Used to implement sampling or rate limiting if needed
 */
declare function shouldSkipEvent(eventName: string, sampleRate?: number): boolean;

type BlocksFieldConfig = {
    blocks: BlockDefinitions;
    discriminator: string;
};
declare function getBlocksFieldConfig(fieldOptions: any): BlocksFieldConfig | null;
declare function parseBlocksValue(value: unknown, config: BlocksFieldConfig): {
    value: any[];
    errors: string[];
};

export { generateInstallationId, generateProjectId, generateSlug, getBlocksFieldConfig, getDefaultTelemetryConfig, getTelemetryConfig, isTelemetryEnabled, parseBlocksValue, sanitizeErrorMessage, sanitizeRoute, shouldSkipEvent };
