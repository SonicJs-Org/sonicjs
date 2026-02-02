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
  /** Wildcard URL match (prefix/contains) - syncs to Cloudflare */
  WILDCARD = 1,
  /** Regular expression pattern match - NOT synced to Cloudflare */
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
  /** Whether to preserve query string when redirecting (Cloudflare: preserve_query_string) */
  preserveQueryString: boolean
  /** Whether to include subdomains in matching (Cloudflare: include_subdomains) */
  includeSubdomains: boolean
  /** Whether to enable subpath matching (Cloudflare: subpath_matching) */
  subpathMatching: boolean
  /** Whether to preserve path suffix when redirecting (Cloudflare: preserve_path_suffix) */
  preservePathSuffix: boolean
  /** Number of times this redirect has been triggered (populated via JOIN with redirect_analytics) */
  hitCount?: number
  /** Timestamp of last redirect hit in milliseconds (populated via JOIN with redirect_analytics) */
  lastHitAt?: number | null
  /** Name of user who created this redirect (populated via JOIN with users table) */
  createdByName?: string
  /** User ID who last updated this redirect */
  updatedBy?: string
  /** Name of user who last updated this redirect (populated via JOIN with users table) */
  updatedByName?: string
  /** Plugin ID that created this redirect (null if created via admin UI) */
  sourcePlugin?: string | null
  /** Timestamp when redirect was soft-deleted (null if not deleted) */
  deletedAt?: number | null
}

/**
 * Redirect management plugin settings
 */
export interface RedirectSettings {
  /** Whether redirect processing is enabled */
  enabled: boolean
  /** Whether to auto-sync eligible redirects to Cloudflare Bulk Redirects */
  autoOffloadEnabled?: boolean
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
  /** Whether to preserve query string when redirecting (default: false) */
  preserveQueryString?: boolean
  /** Whether to include subdomains in matching (default: false) */
  includeSubdomains?: boolean
  /** Whether to enable subpath matching (default: false) */
  subpathMatching?: boolean
  /** Whether to preserve path suffix when redirecting (default: true) */
  preservePathSuffix?: boolean
  /** Plugin ID that created this redirect (null if created via admin UI) */
  sourcePlugin?: string | null
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
  /** Whether to preserve query string when redirecting */
  preserveQueryString?: boolean
  /** Whether to include subdomains in matching */
  includeSubdomains?: boolean
  /** Whether to enable subpath matching */
  subpathMatching?: boolean
  /** Whether to preserve path suffix when redirecting */
  preservePathSuffix?: boolean
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
  /** Filter by source plugin (null = admin-created, string = plugin ID) */
  sourcePlugin?: string | null
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

/**
 * CSV parsing error with line number context
 */
export interface CSVError {
  /** Line number in CSV file (1-indexed, includes header) */
  line: number
  /** Field name where error occurred */
  field?: string
  /** Value that caused the error */
  value?: string
  /** Error message */
  error: string
}

/**
 * Parsed redirect row from CSV (before validation)
 */
export interface ParsedRedirectRow {
  /** Source URL pattern to match */
  source_url: string
  /** Destination URL to redirect to */
  destination_url: string
  /** Match type as string: 'exact', 'wildcard', 'regex' or '0', '1', '2' */
  match_type: string
  /** HTTP status code as string */
  status_code: string
  /** Active status as string: 'true' or 'false' */
  active: string
  /** Whether to preserve query string when redirecting */
  preserve_query_string?: string
  /** Whether to include subdomains in matching */
  include_subdomains?: string
  /** Whether to enable subpath matching */
  subpath_matching?: string
  /** Whether to preserve path suffix when redirecting */
  preserve_path_suffix?: string
}

/**
 * Result of CSV parsing
 */
export interface CSVParseResult {
  /** Whether parsing and basic validation succeeded */
  isValid: boolean
  /** Successfully parsed rows */
  rows: ParsedRedirectRow[]
  /** Parse errors with line number context */
  errors: CSVError[]
}

/**
 * Duplicate handling strategy for CSV import
 */
export type DuplicateHandling = 'reject' | 'skip' | 'update'

/**
 * Result of batch CSV validation
 */
export interface CSVValidationResult {
  /** Whether validation succeeded (no errors) */
  isValid: boolean
  /** Validated rows ready for database insert */
  validRows: ValidatedRedirectRow[]
  /** Validation errors with line number context */
  errors: CSVError[]
  /** Count of rows skipped due to duplicate handling */
  skipped: number
}

/**
 * Validated redirect row ready for database insert
 */
export interface ValidatedRedirectRow {
  /** Normalized source URL */
  source: string
  /** Destination URL */
  destination: string
  /** Match type (numeric) */
  matchType: MatchType
  /** HTTP status code */
  statusCode: StatusCode
  /** Whether redirect is active */
  isActive: boolean
  /** Whether to preserve query string when redirecting */
  preserveQueryString: boolean
  /** Whether to include subdomains in matching */
  includeSubdomains: boolean
  /** Whether to enable subpath matching */
  subpathMatching: boolean
  /** Whether to preserve path suffix when redirecting */
  preservePathSuffix: boolean
}
