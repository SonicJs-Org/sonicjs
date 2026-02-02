import manifest from '../manifest.json'
import type { RedirectSettings, Redirect, CreateRedirectInput, UpdateRedirectInput, RedirectFilter, RedirectOperationResult, MatchType, StatusCode, ValidatedRedirectRow } from '../types'
import type { D1Database } from '@cloudflare/workers-types'
import { normalizeUrl } from '../utils/url-normalizer'
import { validateRedirect, type ValidationResult } from '../utils/validator'
import { invalidateRedirectCache } from '../middleware/redirect'
import { CloudflareBulkService, isEligibleForSync } from './cloudflare-bulk'

export class RedirectService {
  private cloudflareService: CloudflareBulkService | null = null

  constructor(private db: D1Database, private env?: any) {
    if (env) {
      this.cloudflareService = new CloudflareBulkService(env)
    }
  }

  /**
   * Get plugin settings from the database
   */
  async getSettings(): Promise<{ status: string; data: RedirectSettings }> {
    try {
      const record = await this.db
        .prepare(`SELECT settings, status FROM plugins WHERE id = ?`)
        .bind(manifest.id)
        .first()

      if (!record) {
        return {
          status: 'inactive',
          data: this.getDefaultSettings()
        }
      }

      return {
        status: (record?.status as string) || 'inactive',
        data: record?.settings ? JSON.parse(record.settings as string) : this.getDefaultSettings()
      }
    } catch (error) {
      console.error('Error getting redirect management settings:', error)
      return {
        status: 'inactive',
        data: this.getDefaultSettings()
      }
    }
  }

  /**
   * Get default settings
   */
  getDefaultSettings(): RedirectSettings {
    return {
      enabled: true,
      autoOffloadEnabled: false
    }
  }

  /**
   * Check if Cloudflare auto-offload is enabled and configured
   */
  private async shouldSyncToCloudflare(): Promise<boolean> {
    if (!this.cloudflareService?.isConfigured()) {
      return false
    }
    const { data: settings } = await this.getSettings()
    return settings.autoOffloadEnabled === true
  }

  /**
   * Sync redirect to Cloudflare if enabled (fire-and-forget)
   */
  private async syncToCloudflareIfEnabled(redirect: Redirect): Promise<void> {
    try {
      const shouldSync = await this.shouldSyncToCloudflare()
      if (shouldSync && this.cloudflareService && isEligibleForSync(redirect)) {
        const result = await this.cloudflareService.syncRedirect(redirect)
        if (!result.success) {
          console.error('[RedirectService] Cloudflare sync failed:', result.error)
        }
      }
    } catch (error) {
      // Log but don't throw - Cloudflare sync failures shouldn't block D1 operations
      console.error('[RedirectService] Cloudflare sync error:', error)
    }
  }

  /**
   * Remove redirect from Cloudflare if enabled (fire-and-forget)
   */
  private async removeFromCloudflareIfEnabled(sourceUrl: string): Promise<void> {
    try {
      const shouldSync = await this.shouldSyncToCloudflare()
      if (shouldSync && this.cloudflareService) {
        const result = await this.cloudflareService.removeRedirect(sourceUrl)
        if (!result.success) {
          console.error('[RedirectService] Cloudflare remove failed:', result.error)
        }
      }
    } catch (error) {
      console.error('[RedirectService] Cloudflare remove error:', error)
    }
  }

  // CRUD Operations

  /**
   * Create a new redirect with validation
   */
  async create(input: CreateRedirectInput, userId: string): Promise<RedirectOperationResult> {
    try {
      // Generate unique ID
      const id = crypto.randomUUID()

      // Set defaults for optional fields
      const matchType = input.matchType ?? 0 // MatchType.EXACT
      const statusCode = input.statusCode ?? 301
      const isActive = input.isActive ?? true
      const preserveQueryString = input.preserveQueryString ?? false
      const includeSubdomains = input.includeSubdomains ?? false
      const subpathMatching = input.subpathMatching ?? false
      const preservePathSuffix = input.preservePathSuffix ?? true
      const sourcePlugin = input.sourcePlugin ?? null

      // Load existing redirects for circular detection
      const existingMap = await this.getAllSourceDestinationMap()

      // Validate redirect
      const validation = validateRedirect(input.source, input.destination, existingMap)
      if (!validation.isValid) {
        return {
          success: false,
          redirect: undefined,
          error: validation.error,
          warning: undefined
        }
      }

      // Normalize source URL for storage (lowercase, no trailing slash)
      const normalizedSource = normalizeUrl(input.source)
      const now = Date.now()

      // Insert into database
      // NOTE: Migration 036 adds Cloudflare-aligned columns
      await this.db
        .prepare(`
          INSERT INTO redirects (
            id, source, destination, match_type, status_code, is_active,
            preserve_query_string, include_subdomains, subpath_matching, preserve_path_suffix,
            source_plugin, created_by, created_at, updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          id,
          normalizedSource,
          input.destination,
          matchType,
          statusCode,
          isActive ? 1 : 0,
          preserveQueryString ? 1 : 0,
          includeSubdomains ? 1 : 0,
          subpathMatching ? 1 : 0,
          preservePathSuffix ? 1 : 0,
          sourcePlugin,
          userId,
          now,
          now
        )
        .run()

      // Fetch the created redirect
      const redirect = await this.getById(id)

      // Invalidate cache after successful creation
      invalidateRedirectCache()

      // Sync to Cloudflare if enabled (async, non-blocking)
      if (redirect) {
        this.syncToCloudflareIfEnabled(redirect)
      }

      return {
        success: true,
        redirect: redirect!,
        error: undefined,
        warning: validation.warning
      }
    } catch (error) {
      console.error('Error creating redirect:', error)
      return {
        success: false,
        redirect: undefined,
        error: `Failed to create redirect: ${error instanceof Error ? error.message : String(error)}`,
        warning: undefined
      }
    }
  }

  /**
   * Batch create redirects (for CSV import)
   * Uses D1 batch API for performance
   */
  async batchCreate(rows: ValidatedRedirectRow[], userId: string): Promise<number> {
    const now = Date.now()

    // D1 has 100 parameter limit per statement
    // With 13 columns, max ~7 rows per INSERT
    const BATCH_SIZE = 7
    const statements = []

    for (let i = 0; i < rows.length; i += BATCH_SIZE) {
      const batch = rows.slice(i, i + BATCH_SIZE)

      const placeholders = batch.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ')
      const values = batch.flatMap(r => [
        crypto.randomUUID(),
        r.source,
        r.destination,
        r.matchType,
        r.statusCode,
        r.isActive ? 1 : 0,
        r.preserveQueryString ? 1 : 0,
        r.includeSubdomains ? 1 : 0,
        r.subpathMatching ? 1 : 0,
        r.preservePathSuffix ? 1 : 0,
        userId,
        now,
        now
      ])

      statements.push(
        this.db.prepare(`
          INSERT INTO redirects (
            id, source, destination, match_type, status_code, is_active,
            preserve_query_string, include_subdomains, subpath_matching, preserve_path_suffix,
            created_by, created_at, updated_at
          ) VALUES ${placeholders}
        `).bind(...values)
      )
    }

    // Execute all INSERTs in single batch (transaction)
    await this.db.batch(statements)

    // Invalidate cache
    invalidateRedirectCache()

    // Note: Cloudflare sync for batch imports should be done via manual "Sync Now" button
    // to avoid rate limiting and performance issues

    return rows.length
  }

  /**
   * Get redirect by ID
   */
  async getById(id: string): Promise<Redirect | null> {
    try {
      const row = await this.db
        .prepare(`
          SELECT
            r.id, r.source, r.destination, r.match_type, r.status_code, r.is_active,
            COALESCE(r.preserve_query_string, 0) as preserve_query_string,
            COALESCE(r.include_subdomains, 0) as include_subdomains,
            COALESCE(r.subpath_matching, 0) as subpath_matching,
            COALESCE(r.preserve_path_suffix, 1) as preserve_path_suffix,
            r.source_plugin,
            r.created_by, r.created_at, r.updated_at, r.updated_by,
            COALESCE(a.hit_count, 0) as hit_count,
            a.last_hit_at,
            creator.first_name || ' ' || creator.last_name as created_by_name,
            updater.first_name || ' ' || updater.last_name as updated_by_name
          FROM redirects r
          LEFT JOIN redirect_analytics a ON r.id = a.redirect_id
          LEFT JOIN users creator ON r.created_by = creator.id
          LEFT JOIN users updater ON r.updated_by = updater.id
          WHERE r.id = ? AND r.deleted_at IS NULL
        `)
        .bind(id)
        .first()

      if (!row) {
        return null
      }

      return this.mapRowToRedirect(row)
    } catch (error) {
      console.error('Error getting redirect by ID:', error)
      return null
    }
  }

  /**
   * Update an existing redirect
   */
  async update(id: string, input: UpdateRedirectInput, userId?: string): Promise<RedirectOperationResult> {
    try {
      // Fetch existing redirect
      const existing = await this.getById(id)
      if (!existing) {
        return {
          success: false,
          redirect: undefined,
          error: 'Redirect not found',
          warning: undefined
        }
      }

      // If source or destination changed, validate
      let validation: ValidationResult | undefined
      if (input.source || input.destination) {
        const newSource = input.source ?? existing.source
        const newDestination = input.destination ?? existing.destination

        // Build map excluding current redirect (so we don't detect self as circular)
        const existingMap = await this.getAllSourceDestinationMap()
        existingMap.delete(normalizeUrl(existing.source))

        validation = validateRedirect(newSource, newDestination, existingMap)
        if (!validation.isValid) {
          return {
            success: false,
            redirect: undefined,
            error: validation.error,
            warning: undefined
          }
        }
      }

      // Build update query dynamically based on provided fields
      const updates: string[] = []
      const bindings: any[] = []

      if (input.source !== undefined) {
        updates.push('source = ?')
        bindings.push(normalizeUrl(input.source))
      }
      if (input.destination !== undefined) {
        updates.push('destination = ?')
        bindings.push(input.destination)
      }
      if (input.matchType !== undefined) {
        updates.push('match_type = ?')
        bindings.push(input.matchType)
      }
      if (input.statusCode !== undefined) {
        updates.push('status_code = ?')
        bindings.push(input.statusCode)
      }
      if (input.isActive !== undefined) {
        updates.push('is_active = ?')
        bindings.push(input.isActive ? 1 : 0)
      }
      if (input.preserveQueryString !== undefined) {
        updates.push('preserve_query_string = ?')
        bindings.push(input.preserveQueryString ? 1 : 0)
      }
      if (input.includeSubdomains !== undefined) {
        updates.push('include_subdomains = ?')
        bindings.push(input.includeSubdomains ? 1 : 0)
      }
      if (input.subpathMatching !== undefined) {
        updates.push('subpath_matching = ?')
        bindings.push(input.subpathMatching ? 1 : 0)
      }
      if (input.preservePathSuffix !== undefined) {
        updates.push('preserve_path_suffix = ?')
        bindings.push(input.preservePathSuffix ? 1 : 0)
      }

      // Track who made this update
      if (userId) {
        updates.push('updated_by = ?')
        bindings.push(userId)
      }

      // Always update updated_at
      updates.push('updated_at = ?')
      bindings.push(Date.now())

      // Add ID to bindings
      bindings.push(id)

      if (updates.length === 1) {
        // Only updated_at would change, nothing to do
        return {
          success: true,
          redirect: existing,
          error: undefined,
          warning: undefined
        }
      }

      // Execute update
      await this.db
        .prepare(`UPDATE redirects SET ${updates.join(', ')} WHERE id = ?`)
        .bind(...bindings)
        .run()

      // Fetch updated redirect
      const updated = await this.getById(id)

      // Invalidate cache after successful update
      invalidateRedirectCache()

      // Sync to Cloudflare if enabled (async, non-blocking)
      if (updated) {
        this.syncToCloudflareIfEnabled(updated)
      }

      return {
        success: true,
        redirect: updated!,
        error: undefined,
        warning: validation?.warning
      }
    } catch (error) {
      console.error('Error updating redirect:', error)
      return {
        success: false,
        redirect: undefined,
        error: `Failed to update redirect: ${error instanceof Error ? error.message : String(error)}`,
        warning: undefined
      }
    }
  }

  /**
   * Delete a redirect (soft delete - sets deleted_at timestamp)
   */
  async delete(id: string): Promise<RedirectOperationResult> {
    try {
      // Get redirect before deleting (for Cloudflare sync)
      const redirect = await this.getById(id)

      const now = Date.now()
      const result = await this.db
        .prepare(`UPDATE redirects SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`)
        .bind(now, id)
        .run()

      if (result.meta.changes > 0) {
        // Invalidate cache after successful deletion
        invalidateRedirectCache()

        // Remove from Cloudflare if enabled (async, non-blocking)
        if (redirect) {
          this.removeFromCloudflareIfEnabled(redirect.source)
        }

        return {
          success: true,
          redirect: undefined,
          error: undefined,
          warning: undefined
        }
      } else {
        return {
          success: false,
          redirect: undefined,
          error: 'Redirect not found',
          warning: undefined
        }
      }
    } catch (error) {
      console.error('Error deleting redirect:', error)
      return {
        success: false,
        redirect: undefined,
        error: `Failed to delete redirect: ${error instanceof Error ? error.message : String(error)}`,
        warning: undefined
      }
    }
  }

  /**
   * List redirects with optional filtering and pagination
   */
  async list(filter?: RedirectFilter): Promise<Redirect[]> {
    try {
      const conditions: string[] = ['r.deleted_at IS NULL']
      const bindings: any[] = []

      // Build WHERE clause from filters
      if (filter?.isActive !== undefined) {
        conditions.push('r.is_active = ?')
        bindings.push(filter.isActive ? 1 : 0)
      }
      if (filter?.statusCode !== undefined) {
        conditions.push('r.status_code = ?')
        bindings.push(filter.statusCode)
      }
      if (filter?.matchType !== undefined) {
        conditions.push('r.match_type = ?')
        bindings.push(filter.matchType)
      }
      if (filter?.search) {
        conditions.push('(r.source LIKE ? OR r.destination LIKE ?)')
        const searchPattern = `%${filter.search}%`
        bindings.push(searchPattern, searchPattern)
      }
      if (filter?.sourcePlugin !== undefined) {
        if (filter.sourcePlugin === null) {
          conditions.push('r.source_plugin IS NULL')
        } else {
          conditions.push('r.source_plugin = ?')
          bindings.push(filter.sourcePlugin)
        }
      }

      const whereClause = `WHERE ${conditions.join(' AND ')}`

      // Build query with pagination
      const limit = filter?.limit ?? 50
      const offset = filter?.offset ?? 0

      const query = `
        SELECT
          r.id, r.source, r.destination, r.match_type, r.status_code, r.is_active,
          COALESCE(r.preserve_query_string, 0) as preserve_query_string,
          COALESCE(r.include_subdomains, 0) as include_subdomains,
          COALESCE(r.subpath_matching, 0) as subpath_matching,
          COALESCE(r.preserve_path_suffix, 1) as preserve_path_suffix,
          r.source_plugin,
          r.created_by, r.created_at, r.updated_at, r.updated_by,
          COALESCE(a.hit_count, 0) as hit_count,
          a.last_hit_at,
          creator.first_name || ' ' || creator.last_name as created_by_name,
          updater.first_name || ' ' || updater.last_name as updated_by_name
        FROM redirects r
        LEFT JOIN redirect_analytics a ON r.id = a.redirect_id
        LEFT JOIN users creator ON r.created_by = creator.id
        LEFT JOIN users updater ON r.updated_by = updater.id
        ${whereClause}
        ORDER BY r.created_at DESC
        LIMIT ? OFFSET ?
      `

      bindings.push(limit, offset)

      const result = await this.db.prepare(query).bind(...bindings).all()

      return result.results.map(row => this.mapRowToRedirect(row))
    } catch (error) {
      console.error('Error listing redirects:', error)
      return []
    }
  }

  /**
   * Count redirects matching filter (for pagination)
   */
  async count(filter?: RedirectFilter): Promise<number> {
    try {
      const conditions: string[] = ['deleted_at IS NULL']
      const bindings: any[] = []

      // Build WHERE clause from filters (same as list())
      if (filter?.isActive !== undefined) {
        conditions.push('is_active = ?')
        bindings.push(filter.isActive ? 1 : 0)
      }
      if (filter?.statusCode !== undefined) {
        conditions.push('status_code = ?')
        bindings.push(filter.statusCode)
      }
      if (filter?.matchType !== undefined) {
        conditions.push('match_type = ?')
        bindings.push(filter.matchType)
      }
      if (filter?.search) {
        conditions.push('(source LIKE ? OR destination LIKE ?)')
        const searchPattern = `%${filter.search}%`
        bindings.push(searchPattern, searchPattern)
      }
      if (filter?.sourcePlugin !== undefined) {
        if (filter.sourcePlugin === null) {
          conditions.push('source_plugin IS NULL')
        } else {
          conditions.push('source_plugin = ?')
          bindings.push(filter.sourcePlugin)
        }
      }

      const whereClause = `WHERE ${conditions.join(' AND ')}`

      const result = await this.db
        .prepare(`SELECT COUNT(*) as count FROM redirects ${whereClause}`)
        .bind(...bindings)
        .first()

      return (result?.count as number) ?? 0
    } catch (error) {
      console.error('Error counting redirects:', error)
      return 0
    }
  }

  /**
   * Lookup redirect by source URL (used by middleware)
   */
  async lookupBySource(normalizedSource: string): Promise<Redirect | null> {
    try {
      const row = await this.db
        .prepare(`
          SELECT
            id, source, destination, match_type, status_code, is_active,
            COALESCE(preserve_query_string, 0) as preserve_query_string,
            COALESCE(include_subdomains, 0) as include_subdomains,
            COALESCE(subpath_matching, 0) as subpath_matching,
            COALESCE(preserve_path_suffix, 1) as preserve_path_suffix,
            created_by, created_at, updated_at
          FROM redirects
          WHERE LOWER(source) = ? AND is_active = 1 AND deleted_at IS NULL
          LIMIT 1
        `)
        .bind(normalizedSource.toLowerCase())
        .first()

      if (!row) {
        return null
      }

      return this.mapRowToRedirect(row)
    } catch (error) {
      console.error('Error looking up redirect by source:', error)
      return null
    }
  }

  /**
   * Get all source->destination mappings for circular detection
   * @internal Helper method for validation
   */
  async getAllSourceDestinationMap(): Promise<Map<string, string>> {
    try {
      const result = await this.db
        .prepare(`SELECT source, destination FROM redirects WHERE is_active = 1 AND deleted_at IS NULL`)
        .all()

      const map = new Map<string, string>()
      for (const row of result.results) {
        const normalizedSource = normalizeUrl(row.source as string)
        map.set(normalizedSource, row.destination as string)
      }

      return map
    } catch (error) {
      console.error('Error getting source-destination map:', error)
      return new Map()
    }
  }

  /**
   * Map database row to Redirect type
   * @internal Helper method for type conversion
   */
  private mapRowToRedirect(row: any): Redirect {
    const redirect: Redirect = {
      id: row.id as string,
      source: row.source as string,
      destination: row.destination as string,
      matchType: row.match_type as MatchType,
      statusCode: row.status_code as StatusCode,
      isActive: row.is_active === 1,
      preserveQueryString: (row.preserve_query_string ?? 0) === 1,
      includeSubdomains: (row.include_subdomains ?? 0) === 1,
      subpathMatching: (row.subpath_matching ?? 0) === 1,
      preservePathSuffix: (row.preserve_path_suffix ?? 1) === 1,
      createdBy: row.created_by as string,
      createdAt: row.created_at as number,
      updatedAt: row.updated_at as number
    }

    // Add optional analytics fields if present
    if (row.hit_count !== undefined) {
      redirect.hitCount = (row.hit_count ?? 0) as number
    }
    if (row.last_hit_at !== undefined) {
      redirect.lastHitAt = row.last_hit_at as number | null
    }
    if (row.created_by_name) {
      redirect.createdByName = row.created_by_name as string
    }
    if (row.updated_by_name) {
      redirect.updatedByName = row.updated_by_name as string
    }
    if (row.updated_by !== undefined) {
      redirect.updatedBy = row.updated_by as string
    }
    if (row.source_plugin !== undefined) {
      redirect.sourcePlugin = row.source_plugin as string | null
    }
    if (row.deleted_at !== undefined) {
      redirect.deletedAt = row.deleted_at as number | null
    }

    return redirect
  }

  /**
   * Sync all eligible redirects to Cloudflare (manual sync)
   */
  async syncAllToCloudflare(): Promise<{ success: boolean; itemsAdded?: number; error?: string }> {
    if (!this.cloudflareService?.isConfigured()) {
      return { success: false, error: 'Cloudflare not configured. Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID environment variables.' }
    }

    try {
      // Fetch all active redirects
      const redirects = await this.list({ isActive: true, limit: 10000 })
      const result = await this.cloudflareService.syncAll(redirects)
      return result
    } catch (error) {
      console.error('[RedirectService] Full Cloudflare sync error:', error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to sync to Cloudflare'
      }
    }
  }

  /**
   * Check if Cloudflare integration is configured
   */
  isCloudflareConfigured(): boolean {
    return this.cloudflareService?.isConfigured() ?? false
  }

  /**
   * Save plugin settings to the database
   */
  async saveSettings(settings: RedirectSettings): Promise<void> {
    try {
      console.log('[RedirectService.saveSettings] Starting save for plugin:', manifest.id)
      console.log('[RedirectService.saveSettings] Settings:', JSON.stringify(settings))

      // Check if plugin row exists
      const existing = await this.db
        .prepare(`SELECT id, status FROM plugins WHERE id = ?`)
        .bind(manifest.id)
        .first()

      console.log('[RedirectService.saveSettings] Existing row:', JSON.stringify(existing))

      if (existing) {
        // Update existing row
        console.log('[RedirectService.saveSettings] Updating existing row...')
        const result = await this.db
          .prepare(`UPDATE plugins SET settings = ?, last_updated = ? WHERE id = ?`)
          .bind(JSON.stringify(settings), Date.now(), manifest.id)
          .run()
        console.log('[RedirectService.saveSettings] UPDATE result:', JSON.stringify(result))
        console.log('[RedirectService.saveSettings] Successfully updated')
      } else {
        // Insert new row
        console.log('[RedirectService.saveSettings] No existing row, inserting new...')
        const result = await this.db
          .prepare(`
            INSERT INTO plugins (id, name, display_name, description, version, author, category, status, settings, installed_at, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'inactive', ?, ?, ?)
          `)
          .bind(
            manifest.id,
            manifest.id,
            manifest.name,
            manifest.description || '',
            manifest.version || '1.0.0',
            manifest.author || 'Unknown',
            manifest.category || 'other',
            JSON.stringify(settings),
            Date.now(),
            Date.now()
          )
          .run()
        console.log('[RedirectService.saveSettings] INSERT result:', JSON.stringify(result))
        console.log('[RedirectService.saveSettings] Successfully inserted')
      }
      console.log('[RedirectService.saveSettings] Settings saved successfully')
    } catch (error) {
      console.error('[RedirectService.saveSettings] ERROR:', error)
      console.error('[RedirectService.saveSettings] Error message:', error instanceof Error ? error.message : String(error))
      console.error('[RedirectService.saveSettings] Error stack:', error instanceof Error ? error.stack : 'No stack')
      throw new Error(`Failed to save redirect management settings: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  // Lifecycle methods
  /**
   * Install the plugin (create database entry)
   */
  async install(): Promise<void> {
    try {
      const defaultSettings = this.getDefaultSettings()
      await this.db
        .prepare(`
          INSERT INTO plugins (
            id, name, display_name, description, version, author,
            category, status, settings, installed_at, last_updated
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, 'inactive', ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            display_name = excluded.display_name,
            description = excluded.description,
            version = excluded.version,
            updated_at = excluded.last_updated
        `)
        .bind(
          manifest.id,
          manifest.id,
          manifest.name,
          manifest.description,
          manifest.version,
          manifest.author,
          manifest.category,
          JSON.stringify(defaultSettings),
          Date.now(),
          Date.now()
        )
        .run()
      console.log('Redirect management plugin installed successfully')
    } catch (error) {
      console.error('Error installing redirect management plugin:', error)
      throw new Error('Failed to install redirect management plugin')
    }
  }

  /**
   * Activate the plugin
   */
  async activate(): Promise<void> {
    try {
      await this.db
        .prepare(`
          UPDATE plugins
          SET status = 'active', last_updated = ?
          WHERE id = ?
        `)
        .bind(Date.now(), manifest.id)
        .run()
      console.log('Redirect management plugin activated')
    } catch (error) {
      console.error('Error activating redirect management plugin:', error)
      throw new Error('Failed to activate redirect management plugin')
    }
  }

  /**
   * Deactivate the plugin
   */
  async deactivate(): Promise<void> {
    try {
      await this.db
        .prepare(`
          UPDATE plugins
          SET status = 'inactive', last_updated = ?
          WHERE id = ?
        `)
        .bind(Date.now(), manifest.id)
        .run()
      console.log('Redirect management plugin deactivated')
    } catch (error) {
      console.error('Error deactivating redirect management plugin:', error)
      throw new Error('Failed to deactivate redirect management plugin')
    }
  }

  /**
   * Uninstall the plugin (remove database entry)
   */
  async uninstall(): Promise<void> {
    try {
      await this.db
        .prepare(`DELETE FROM plugins WHERE id = ?`)
        .bind(manifest.id)
        .run()
      console.log('Redirect management plugin uninstalled')
    } catch (error) {
      console.error('Error uninstalling redirect management plugin:', error)
      throw new Error('Failed to uninstall redirect management plugin')
    }
  }
}
