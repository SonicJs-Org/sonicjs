/**
 * HTML sanitization utilities for preventing XSS attacks
 */

/**
 * Escapes HTML special characters to prevent XSS attacks
 * @param text - The text to escape
 * @returns The escaped text safe for HTML output
 */
export function escapeHtml(text: string): string {
  if (typeof text !== 'string') {
    return ''
  }

  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  }

  return text.replace(/[&<>"']/g, (char) => map[char] || char)
}

/**
 * Sanitizes user input by escaping HTML special characters
 * This should be used for all user-provided text fields to prevent XSS
 * @param input - The input string to sanitize
 * @returns The sanitized string
 */
export function sanitizeInput(input: string | null | undefined): string {
  if (!input) {
    return ''
  }
  return escapeHtml(String(input).trim())
}

/**
 * Sanitizes rich text HTML by stripping dangerous elements while preserving
 * legitimate formatting. Removes script tags, event handlers, and javascript: URLs.
 * @param html - The rich text HTML to sanitize
 * @returns Sanitized HTML safe for rendering
 */
export function sanitizeRichText(html: string): string {
  if (typeof html !== 'string') {
    return ''
  }

  return html
    // Remove script tags and their contents
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    // Remove event handler attributes (on*)
    .replace(/\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    // Remove javascript: URLs in href/src/action attributes
    .replace(/(href|src|action)\s*=\s*"javascript:[^"]*"/gi, '$1=""')
    .replace(/(href|src|action)\s*=\s*'javascript:[^']*'/gi, "$1=''")
}

/**
 * Sanitizes an object's string properties
 * @param obj - Object with string properties to sanitize
 * @param fields - Array of field names to sanitize
 * @returns New object with sanitized fields
 */
export function sanitizeObject<T extends Record<string, any>>(
  obj: T,
  fields: (keyof T)[]
): T {
  const sanitized = { ...obj }

  for (const field of fields) {
    if (typeof obj[field] === 'string') {
      sanitized[field] = sanitizeInput(obj[field]) as T[keyof T]
    }
  }

  return sanitized
}
