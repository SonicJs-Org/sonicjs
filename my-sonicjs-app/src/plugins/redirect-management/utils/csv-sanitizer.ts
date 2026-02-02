/**
 * CSV Sanitizer Utility
 *
 * Prevents CSV formula injection and ensures proper RFC 4180 escaping
 * Following OWASP guidance: https://owasp.org/www-community/attacks/CSV_Injection
 */

/**
 * Sanitizes a field value for CSV export
 *
 * - Prevents formula injection by prefixing dangerous characters with '
 * - Handles RFC 4180 escaping for fields containing commas, quotes, or newlines
 * - Doubles internal quotes for proper CSV escaping
 *
 * @param value - The value to sanitize (string, null, or undefined)
 * @returns Sanitized CSV-safe string
 *
 * @example
 * sanitizeCSVField('=SUM(A1:A10)') // Returns '=SUM(A1:A10)' (prefixed to prevent formula)
 * sanitizeCSVField('Hello, World') // Returns '"Hello, World"' (quoted for comma)
 * sanitizeCSVField('Say "Hello"') // Returns '"Say ""Hello"""' (quoted and escaped)
 */
export function sanitizeCSVField(value: string | null | undefined): string {
  // Handle null/undefined/empty
  if (!value) return ''

  const str = String(value)

  // Check if starts with dangerous character (formula injection prevention)
  const dangerousChars = ['=', '+', '-', '@', '\t', '\r']
  if (dangerousChars.some(char => str.startsWith(char))) {
    // Prefix with single quote to force text treatment in spreadsheets
    return `'${str.replace(/"/g, '""')}`
  }

  // Check if needs quoting per RFC 4180 (contains comma, quote, or newline)
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    // Escape quotes by doubling, wrap in quotes
    return `"${str.replace(/"/g, '""')}"`
  }

  // No sanitization needed
  return str
}
