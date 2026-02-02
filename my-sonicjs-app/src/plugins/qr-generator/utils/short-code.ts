/**
 * Short code generation utility for QR-to-redirect integration
 *
 * Generates 6-character alphanumeric codes for redirect paths /qr/{code}
 * Uses nanoid's customAlphabet for URL-safe, collision-resistant codes
 */
import { customAlphabet } from 'nanoid'

// 62-character alphanumeric alphabet (URL-safe)
const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

/**
 * Generate a 6-character alphanumeric short code
 *
 * With 62 characters and 6 positions: 62^6 = 56.8 billion combinations
 * At 1000 codes/day, would take ~156,000 years to exhaust
 */
const generateShortCode = customAlphabet(alphabet, 6)

export { generateShortCode }

/**
 * Generate a unique short code by checking against existing redirects
 *
 * @param db - D1 database instance
 * @param maxAttempts - Maximum retry attempts before failing (default: 3)
 * @returns Promise resolving to unique 6-character code
 * @throws Error if unable to generate unique code after maxAttempts
 */
export async function generateUniqueShortCode(
  db: D1Database,
  maxAttempts = 3
): Promise<string> {
  for (let i = 0; i < maxAttempts; i++) {
    const code = generateShortCode()

    // Check if this short code already exists in redirects table
    const existing = await db
      .prepare(`SELECT 1 FROM redirects WHERE source = ? LIMIT 1`)
      .bind(`/qr/${code}`)
      .first()

    if (!existing) {
      return code
    }
  }

  throw new Error('Failed to generate unique short code after multiple attempts')
}
