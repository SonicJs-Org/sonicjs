/**
 * Redirect Integration Facade
 *
 * Provides a facade for QR-to-redirect integration, allowing QRService
 * to interact with the redirect-management module for scan tracking,
 * source path generation, and cache invalidation.
 *
 * Note: Actual redirect CRUD operations are done via D1 batch() in QRService
 * for atomicity. We don't use RedirectService.create() because we need to
 * batch QR + redirect inserts together as a single transaction.
 */
import type { D1Database } from '@cloudflare/workers-types'
import { MatchType } from '../../redirect-management/types'
import { invalidateRedirectCache } from '../../redirect-management/middleware/redirect'

export { MatchType }

export class RedirectIntegration {
  constructor(private db: D1Database) {}

  /**
   * Build the redirect source path for a given short code
   * QR redirects use the format /qr/{shortCode}
   *
   * @param shortCode - 6-character alphanumeric short code
   * @returns Source path for the redirect
   */
  getSourcePath(shortCode: string): string {
    return `/qr/${shortCode}`
  }

  /**
   * Get the scan count for a QR code by its short code
   * Looks up the associated redirect's hit count from analytics
   *
   * @param shortCode - 6-character alphanumeric short code
   * @returns Number of times the QR code has been scanned
   */
  async getScanCount(shortCode: string): Promise<number> {
    const result = await this.db
      .prepare(`
        SELECT COALESCE(a.hit_count, 0) as hit_count
        FROM redirects r
        LEFT JOIN redirect_analytics a ON r.id = a.redirect_id
        WHERE r.source = ? AND r.deleted_at IS NULL
      `)
      .bind(this.getSourcePath(shortCode))
      .first()
    return (result?.hit_count as number) ?? 0
  }

  /**
   * Check if a redirect exists for the given short code
   * Useful for validating short codes or checking for collisions
   *
   * @param shortCode - 6-character alphanumeric short code
   * @returns True if a redirect exists for this short code
   */
  async redirectExists(shortCode: string): Promise<boolean> {
    const result = await this.db
      .prepare(`SELECT 1 FROM redirects WHERE source = ? LIMIT 1`)
      .bind(this.getSourcePath(shortCode))
      .first()
    return !!result
  }

  /**
   * Invalidate the redirect cache
   * Should be called after any redirect modifications (create, update, delete)
   */
  invalidateCache(): void {
    invalidateRedirectCache()
  }
}
