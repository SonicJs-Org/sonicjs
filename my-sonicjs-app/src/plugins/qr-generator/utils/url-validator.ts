export interface UrlValidationResult {
  valid: boolean
  error?: string
  normalizedUrl?: string
}

const VALID_SCHEMES = ['http://', 'https://', 'mailto:', 'tel:', 'sms:']
const MAX_URL_LENGTH = 500

export function validateDestinationUrl(url: string): UrlValidationResult {
  if (!url || url.trim() === '') {
    return { valid: false, error: 'URL cannot be empty' }
  }

  const trimmed = url.trim()

  // Check length (QR code capacity)
  if (trimmed.length > MAX_URL_LENGTH) {
    return {
      valid: false,
      error: `URL exceeds ${MAX_URL_LENGTH} characters. Consider using a URL shortener.`
    }
  }

  // Check scheme
  const hasValidScheme = VALID_SCHEMES.some(scheme =>
    trimmed.toLowerCase().startsWith(scheme)
  )

  if (!hasValidScheme) {
    return {
      valid: false,
      error: 'URL must start with http://, https://, mailto:, tel:, or sms:'
    }
  }

  return { valid: true, normalizedUrl: trimmed }
}
