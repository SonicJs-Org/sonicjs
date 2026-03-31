/**
 * URL Normalization Utilities
 *
 * Provides consistent URL comparison for redirect matching:
 * - Case-insensitive matching (lowercase)
 * - Trailing slash normalization (strip except root)
 * - Query parameter handling (configurable)
 */

/**
 * Normalize URL for consistent redirect matching
 *
 * Transformations:
 * - Convert to lowercase for case-insensitive matching
 * - Remove trailing slash EXCEPT for root "/"
 * - Handle edge cases: empty string returns "/", null/undefined returns "/"
 * - Preserve encoded characters (do NOT decode URI components)
 *
 * Examples:
 * - "/Blog" -> "/blog"
 * - "/page/" -> "/page"
 * - "/" -> "/"
 * - "" -> "/"
 * - "/Page%20Name" -> "/page%20name" (preserves encoding)
 *
 * @param url - URL path to normalize
 * @returns Normalized URL path
 */
export function normalizeUrl(url: string): string {
  // Handle edge cases: empty, null, undefined
  if (!url || url.trim() === '') {
    return '/'
  }

  // 1. Convert to lowercase for case-insensitive matching
  let normalized = url.toLowerCase()

  // 2. Remove trailing slash (except root "/")
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1)
  }

  // 3. Do NOT decode URI components - preserve encoded characters
  // This ensures "/page%20name" matches exactly as stored

  return normalized
}

/**
 * Normalize URL with optional query parameter handling
 *
 * First normalizes the URL path using normalizeUrl(), then:
 * - If includeQuery is false: Strip query string (everything after ?)
 * - If includeQuery is true: Keep query string intact
 *
 * Examples:
 * - "/Page?ref=email" with includeQuery=false -> "/page"
 * - "/Page?ref=email" with includeQuery=true -> "/page?ref=email"
 * - "/Blog/" with includeQuery=false -> "/blog"
 * - "/Blog/" with includeQuery=true -> "/blog"
 *
 * @param url - URL path to normalize
 * @param includeQuery - Whether to include query parameters in normalized result
 * @returns Normalized URL path with or without query string
 */
export function normalizeUrlWithQuery(url: string, includeQuery: boolean): string {
  // First normalize the URL path
  const normalized = normalizeUrl(url)

  // If we should exclude query params, strip everything after ?
  if (!includeQuery) {
    const queryIndex = normalized.indexOf('?')
    if (queryIndex !== -1) {
      return normalized.slice(0, queryIndex)
    }
  }

  // Otherwise, return with query params intact
  return normalized
}
