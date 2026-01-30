/**
 * Redirect Management Plugin Types
 *
 * Type definitions for the redirect management plugin
 */

/**
 * Match type enum for redirect patterns
 */
export enum MatchType {
  /** Exact URL match */
  EXACT = 0,
  /** Partial URL match (contains) */
  PARTIAL = 1,
  /** Regular expression pattern match */
  REGEX = 2
}

/**
 * HTTP status codes supported for redirects
 */
export type StatusCode = 301 | 302 | 307 | 308 | 410

/**
 * Redirect interface
 */
export interface Redirect {
  /** Unique identifier */
  id: string
  /** Source URL pattern to match */
  source: string
  /** Destination URL to redirect to */
  destination: string
  /** Type of pattern matching to use */
  matchType: MatchType
  /** HTTP status code for the redirect */
  statusCode: StatusCode
  /** Whether this redirect is currently active */
  isActive: boolean
  /** User ID who created this redirect */
  createdBy: string
  /** Timestamp when redirect was created (milliseconds) */
  createdAt: number
  /** Timestamp when redirect was last updated (milliseconds) */
  updatedAt: number
  /** Whether to include query params in URL matching */
  includeQueryParams: boolean
  /** Whether to preserve query params when redirecting */
  preserveQueryParams: boolean
}

/**
 * Redirect management plugin settings
 */
export interface RedirectSettings {
  /** Whether redirect processing is enabled */
  enabled: boolean
}

/**
 * Redirect analytics tracking
 */
export interface RedirectAnalytics {
  /** Unique identifier */
  id: string
  /** Associated redirect ID */
  redirectId: string
  /** Number of times this redirect has been triggered */
  hitCount: number
  /** Timestamp of last redirect hit (milliseconds, nullable) */
  lastHitAt: number | null
  /** Timestamp when analytics record was created */
  createdAt: number
  /** Timestamp when analytics record was last updated */
  updatedAt: number
}

/**
 * Input type for creating a new redirect
 */
export interface CreateRedirectInput {
  /** Source URL pattern to match */
  source: string
  /** Destination URL to redirect to */
  destination: string
  /** Type of pattern matching to use (default: EXACT) */
  matchType?: MatchType
  /** HTTP status code for the redirect (default: 301) */
  statusCode?: StatusCode
  /** Whether this redirect is currently active (default: true) */
  isActive?: boolean
  /** Whether to include query params in URL matching (default: false) */
  includeQueryParams?: boolean
  /** Whether to preserve query params when redirecting (default: false) */
  preserveQueryParams?: boolean
}

/**
 * Input type for updating an existing redirect
 */
export interface UpdateRedirectInput {
  /** Source URL pattern to match */
  source?: string
  /** Destination URL to redirect to */
  destination?: string
  /** Type of pattern matching to use */
  matchType?: MatchType
  /** HTTP status code for the redirect */
  statusCode?: StatusCode
  /** Whether this redirect is currently active */
  isActive?: boolean
  /** Whether to include query params in URL matching */
  includeQueryParams?: boolean
  /** Whether to preserve query params when redirecting */
  preserveQueryParams?: boolean
}

/**
 * Filter options for listing redirects
 */
export interface RedirectFilter {
  /** Filter by active status */
  isActive?: boolean
  /** Filter by status code */
  statusCode?: StatusCode
  /** Filter by match type */
  matchType?: MatchType
  /** Search term (searches source and destination) */
  search?: string
  /** Maximum number of results to return (default: 50) */
  limit?: number
  /** Number of results to skip (for pagination) */
  offset?: number
}

/**
 * Result of a redirect operation (create, update, delete)
 */
export interface RedirectOperationResult {
  /** Whether the operation was successful */
  success: boolean
  /** The redirect object (if operation succeeded) */
  redirect?: Redirect | undefined
  /** Error message (if operation failed) */
  error?: string | undefined
  /** Warning message (if operation succeeded but with warnings) */
  warning?: string | undefined
}
