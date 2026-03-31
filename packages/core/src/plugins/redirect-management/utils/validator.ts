/**
 * Redirect Validation Utilities
 *
 * Provides validation for redirect configurations:
 * - Circular redirect detection (A->B->A)
 * - Redirect chain detection (A->B->C->D)
 * - URL format validation
 * - Optional destination existence checking
 */

import { normalizeUrl } from './url-normalizer'

/**
 * Result of a validation check
 */
export interface ValidationResult {
  /** Whether the validation passed */
  isValid: boolean
  /** Error message if validation failed */
  error?: string
  /** Warning message (valid but concerning) */
  warning?: string
  /** Number of hops in redirect chain */
  chainLength?: number
  /** URLs in the redirect chain */
  chainUrls?: string[]
}

/**
 * Detect if adding a redirect would create a circular loop
 *
 * Uses a visited-set pattern to detect cycles by following the redirect chain.
 * Also detects long chains (3+ hops) and returns warnings.
 *
 * Algorithm:
 * 1. Start with source URL in visited set
 * 2. Follow destination through existing redirects
 * 3. If we reach a URL already visited -> circular (invalid)
 * 4. If chain length >= 3 -> valid but warning
 * 5. Safety limit: stop at 10 hops (error)
 *
 * Examples:
 * - A->B with existing B->A: CIRCULAR (invalid)
 * - A->B with existing B->C, C->D: Valid with warning (3 hops)
 * - A->B with no existing redirects: Valid
 *
 * @param source - Source URL of the new redirect
 * @param destination - Destination URL of the new redirect
 * @param existingRedirects - Map of source URL -> destination URL for all existing redirects
 * @returns ValidationResult indicating if redirect is valid
 */
export function detectCircularRedirect(
  source: string,
  destination: string,
  existingRedirects: Map<string, string>
): ValidationResult {
  // Normalize URLs for case-insensitive comparison
  const normalizedSource = normalizeUrl(source)
  const normalizedDest = normalizeUrl(destination)

  // Check for self-redirect (source equals destination)
  if (normalizedSource === normalizedDest) {
    return {
      isValid: false,
      error: `Self-redirect detected: ${normalizedSource} redirects to itself`,
      chainLength: 1,
      chainUrls: [normalizedSource, normalizedDest]
    }
  }

  // Track visited URLs to detect cycles
  const visited = new Set<string>()
  visited.add(normalizedSource)

  // Track chain for debugging and warnings
  const chainUrls = [normalizedSource, normalizedDest]
  let current = normalizedDest
  let chainLength = 1

  // Safety limit to prevent infinite loops
  const MAX_CHAIN_LENGTH = 10

  // Follow the redirect chain
  while (true) {
    // Check if current URL is already visited (circular redirect)
    if (visited.has(current)) {
      return {
        isValid: false,
        error: `Circular redirect detected: ${chainUrls.join(' -> ')}`,
        chainLength,
        chainUrls
      }
    }

    // If current URL doesn't have a redirect, chain ends here
    if (!existingRedirects.has(current)) {
      break
    }

    // Add current URL to visited set
    visited.add(current)

    // Move to next destination in chain
    const next = existingRedirects.get(current)!
    const normalizedNext = normalizeUrl(next)
    chainUrls.push(normalizedNext)
    current = normalizedNext
    chainLength++

    // Safety limit check
    if (chainLength > MAX_CHAIN_LENGTH) {
      return {
        isValid: false,
        error: `Redirect chain exceeds safety limit of ${MAX_CHAIN_LENGTH} hops`,
        chainLength,
        chainUrls
      }
    }
  }

  // Check for long chains (3+ hops)
  if (chainLength >= 3) {
    return {
      isValid: true,
      warning: `Redirect chain has ${chainLength} hops: ${chainUrls.join(' -> ')}. Consider simplifying.`,
      chainLength,
      chainUrls
    }
  }

  // Valid redirect
  return {
    isValid: true,
    chainLength,
    chainUrls
  }
}

/**
 * Validate URL format
 *
 * Checks:
 * - URL is non-empty
 * - URL starts with "/" (relative) OR "http://" or "https://" (absolute)
 *
 * Does NOT validate if destination exists - that's a separate concern.
 * This is basic format checking only.
 *
 * Examples:
 * - "/page" -> valid (relative)
 * - "https://example.com" -> valid (absolute)
 * - "page" -> invalid (missing leading slash)
 * - "" -> invalid (empty)
 *
 * @param url - URL to validate
 * @returns ValidationResult indicating if URL format is valid
 */
export function validateUrl(url: string): ValidationResult {
  // Check for empty URL
  if (!url || url.trim() === '') {
    return {
      isValid: false,
      error: 'URL cannot be empty'
    }
  }

  const trimmed = url.trim()

  // Check if URL starts with "/" (relative) or "http://" or "https://" (absolute)
  if (trimmed.startsWith('/')) {
    return { isValid: true }
  }

  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return { isValid: true }
  }

  return {
    isValid: false,
    error: 'URL must start with "/" (relative) or "http://" or "https://" (absolute)'
  }
}

/**
 * Validate a redirect configuration
 *
 * Runs all validation checks:
 * 1. Source URL format validation
 * 2. Destination URL format validation
 * 3. Circular redirect detection
 *
 * Returns first error encountered, or warning from circular detection, or valid.
 *
 * @param source - Source URL of the redirect
 * @param destination - Destination URL of the redirect
 * @param existingRedirects - Map of source URL -> destination URL for all existing redirects
 * @returns ValidationResult indicating if redirect is valid
 */
export function validateRedirect(
  source: string,
  destination: string,
  existingRedirects: Map<string, string>
): ValidationResult {
  // Validate source URL format
  const sourceValidation = validateUrl(source)
  if (!sourceValidation.isValid) {
    return {
      isValid: false,
      error: `Invalid source URL: ${sourceValidation.error}`
    }
  }

  // Validate destination URL format
  const destValidation = validateUrl(destination)
  if (!destValidation.isValid) {
    return {
      isValid: false,
      error: `Invalid destination URL: ${destValidation.error}`
    }
  }

  // Check for circular redirects
  const circularCheck = detectCircularRedirect(source, destination, existingRedirects)
  if (!circularCheck.isValid) {
    return circularCheck
  }

  // Return result (may have warning about chain length)
  return circularCheck
}

/**
 * Check if a destination URL exists (optional helper for admin UI)
 *
 * This is an async helper function that attempts to verify if a destination
 * URL is accessible. It returns warnings rather than blocking saves, since:
 * - Internal routes can't be easily checked
 * - Destinations might not exist yet (forward-planning redirects)
 * - Network errors shouldn't prevent redirect creation
 *
 * Behavior:
 * - Relative URLs ("/page"): Always valid (can't check internal routes)
 * - Absolute URLs: Attempt HEAD request with 3-second timeout
 * - 200-399 response: Valid
 * - 404/410: Valid with warning
 * - Network error: Valid with warning (don't block save)
 *
 * @param destination - Destination URL to check
 * @param fetchFn - Optional fetch function (for testing/mocking)
 * @returns ValidationResult with warnings if destination may not exist
 */
export async function checkDestinationExists(
  destination: string,
  fetchFn: typeof fetch = fetch
): Promise<ValidationResult> {
  // Relative URLs - can't easily check internal routes
  if (destination.startsWith('/')) {
    return {
      isValid: true
    }
  }

  // Absolute URLs - attempt HEAD request
  try {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 3000) // 3 second timeout

    const response = await fetchFn(destination, {
      method: 'HEAD',
      signal: controller.signal,
      // Don't follow redirects to check the actual destination
      redirect: 'manual'
    })

    clearTimeout(timeoutId)

    // 200-399 responses are good (including redirects)
    if (response.status >= 200 && response.status < 400) {
      return { isValid: true }
    }

    // 404/410 - destination not found
    if (response.status === 404 || response.status === 410) {
      return {
        isValid: true,
        warning: `Destination returned ${response.status}. The URL may not exist yet.`
      }
    }

    // Other status codes
    return {
      isValid: true,
      warning: `Destination returned status ${response.status}. Please verify the URL is correct.`
    }
  } catch (error) {
    // Network errors, timeouts, etc. - don't block save
    const message = error instanceof Error ? error.message : 'Unknown error'
    return {
      isValid: true,
      warning: `Could not verify destination: ${message}. The URL may still be valid.`
    }
  }
}
