/**
 * HTML sanitization utilities for preventing XSS attacks
 */
/**
 * Escapes HTML special characters to prevent XSS attacks
 * @param text - The text to escape
 * @returns The escaped text safe for HTML output
 */
declare function escapeHtml(text: string): string;
/**
 * Sanitizes user input by escaping HTML special characters
 * This should be used for all user-provided text fields to prevent XSS
 * @param input - The input string to sanitize
 * @returns The sanitized string
 */
declare function sanitizeInput(input: string | null | undefined): string;
/**
 * Sanitizes an object's string properties
 * @param obj - Object with string properties to sanitize
 * @param fields - Array of field names to sanitize
 * @returns New object with sanitized fields
 */
declare function sanitizeObject<T extends Record<string, any>>(obj: T, fields: (keyof T)[]): T;

interface TemplateData {
    [key: string]: any;
}
declare class TemplateRenderer {
    private templateCache;
    constructor();
    /**
     * Simple Handlebars-like template engine
     */
    private renderTemplate;
    /**
     * Get nested value from object using dot notation
     */
    private getNestedValue;
    /**
     * Title case helper function
     */
    private titleCase;
    /**
     * Render a template string with data
     */
    render(template: string, data?: TemplateData): string;
    /**
     * Clear template cache (useful for development)
     */
    clearCache(): void;
}
declare const templateRenderer: TemplateRenderer;
declare function renderTemplate(template: string, data?: TemplateData): string;

/**
 * Query Filter Builder for SonicJS AI
 * Supports comprehensive filtering with AND/OR logic
 * Compatible with D1 Database (SQLite)
 */
type FilterOperator = 'equals' | 'not_equals' | 'greater_than' | 'greater_than_equal' | 'less_than' | 'less_than_equal' | 'like' | 'contains' | 'in' | 'not_in' | 'all' | 'exists' | 'near' | 'within' | 'intersects';
interface FilterCondition {
    field: string;
    operator: FilterOperator;
    value: any;
}
interface FilterGroup {
    and?: FilterCondition[];
    or?: FilterCondition[];
}
interface QueryFilter {
    where?: FilterGroup;
    limit?: number;
    offset?: number;
    sort?: {
        field: string;
        order: 'asc' | 'desc';
    }[];
}
interface QueryResult {
    sql: string;
    params: any[];
    errors: string[];
}
/**
 * Query Filter Builder
 * Converts filter objects into SQL WHERE clauses with parameterized queries
 */
declare class QueryFilterBuilder {
    private params;
    private errors;
    /**
     * Build a complete SQL query from filter object
     */
    build(baseTable: string, filter: QueryFilter): QueryResult;
    /**
     * Build WHERE clause from filter group
     */
    private buildWhereClause;
    /**
     * Build a single condition
     */
    private buildCondition;
    /**
     * Build equals condition
     */
    private buildEquals;
    /**
     * Build not equals condition
     */
    private buildNotEquals;
    /**
     * Build comparison condition (>, >=, <, <=)
     */
    private buildComparison;
    /**
     * Build LIKE condition (case-insensitive, all words must be present)
     */
    private buildLike;
    /**
     * Build CONTAINS condition (case-insensitive substring)
     */
    private buildContains;
    /**
     * Build IN condition
     */
    private buildIn;
    /**
     * Build NOT IN condition
     */
    private buildNotIn;
    /**
     * Build ALL condition (value must contain all items in list)
     * For SQLite, we'll check if a JSON array contains all values
     */
    private buildAll;
    /**
     * Build EXISTS condition
     */
    private buildExists;
    /**
     * Sanitize field names to prevent SQL injection
     */
    private sanitizeFieldName;
    /**
     * Parse filter from query string
     */
    static parseFromQuery(query: Record<string, any>): QueryFilter;
}
/**
 * Helper function to build query from filter
 */
declare function buildQuery(table: string, filter: QueryFilter): QueryResult;

/**
 * Simple in-memory metrics tracker for real-time analytics
 * Tracks requests per second using a sliding window
 */
declare class MetricsTracker {
    private requests;
    private readonly windowSize;
    /**
     * Record a new request
     */
    recordRequest(): void;
    /**
     * Clean up old requests outside the window
     */
    private cleanup;
    /**
     * Get current requests per second
     */
    getRequestsPerSecond(): number;
    /**
     * Get total requests in the current window
     */
    getTotalRequests(): number;
    /**
     * Get average requests per second over the window
     */
    getAverageRPS(): number;
}
declare const metricsTracker: MetricsTracker;

/**
 * Version utility
 *
 * Provides the current version of @sonicjs-cms/core package
 */
declare const SONICJS_VERSION: string;
/**
 * Get the current SonicJS core version
 */
declare function getCoreVersion(): string;

export { type FilterOperator as F, QueryFilterBuilder as Q, SONICJS_VERSION as S, TemplateRenderer as T, sanitizeObject as a, buildQuery as b, type FilterCondition as c, type FilterGroup as d, escapeHtml as e, type QueryFilter as f, type QueryResult as g, getCoreVersion as h, metricsTracker as m, renderTemplate as r, sanitizeInput as s, templateRenderer as t };
