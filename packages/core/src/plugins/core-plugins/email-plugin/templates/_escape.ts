/**
 * Minimal HTML-escape helper shared by the v3 email-plugin's render helpers.
 *
 * The templates inject typed inputs (firstName, email, siteName, code,
 * reset link, etc.) into HTML bodies. All user-derived fields pass through
 * `escapeHtml` before insertion to prevent HTML/attribute injection on
 * recipient mail clients that render HTML.
 *
 * Plain text bodies do not call this (text/plain is opaque to HTML).
 *
 * Kept underscore-prefixed (`_escape`) to mark it as a private module-level
 * util — not exported from the plugin's barrel; consumed only by sibling
 * template files.
 */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}
