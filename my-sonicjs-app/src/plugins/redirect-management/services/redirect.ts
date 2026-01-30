import manifest from '../manifest.json'
import type { RedirectSettings, Redirect, CreateRedirectInput, UpdateRedirectInput, RedirectFilter, RedirectOperationResult, MatchType, StatusCode } from '../types'
import type { D1Database } from '@cloudflare/workers-types'
import { normalizeUrl } from '../utils/url-normalizer'
import { validateRedirect, type ValidationResult } from '../utils/validator'
import { invalidateRedirectCache } from '../middleware/redirect'

export class RedirectService {
  constructor(private db: D1Database) {}

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
      enabled: true
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
      const includeQueryParams = input.includeQueryParams ?? false
      const preserveQueryParams = input.preserveQueryParams ?? false

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
      // NOTE: Migration 033 adds include_query_params and preserve_query_params columns
      // Using COALESCE for backward compatibility with existing rows
      await this.db
        .prepare(`
          INSERT INTO redirects (
            id, source, destination, match_type, status_code, is_active,
            include_query_params, preserve_query_params,
            created_by, created_at, updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          id,
          normalizedSource,
          input.destination,
          matchType,
          statusCode,
          isActive ? 1 : 0,
          includeQueryParams ? 1 : 0,
          preserveQueryParams ? 1 : 0,
          userId,
          now,
          now
        )
        .run()

      // Fetch the created redirect
      const redirect = await this.getById(id)

      // Invalidate cache after successful creation
      invalidateRedirectCache()

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
   * Get redirect by ID
   */
  async getById(id: string): Promise<Redirect | null> {
    try {
      const row = await this.db
        .prepare(`
          SELECT
            id, source, destination, match_type, status_code, is_active,
            COALESCE(include_query_params, 0) as include_query_params,
            COALESCE(preserve_query_params, 0) as preserve_query_params,
            created_by, created_at, updated_at
          FROM redirects
          WHERE id = ?
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
  async update(id: string, input: UpdateRedirectInput): Promise<RedirectOperationResult> {
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
      if (input.includeQueryParams !== undefined) {
        updates.push('include_query_params = ?')
        bindings.push(input.includeQueryParams ? 1 : 0)
      }
      if (input.preserveQueryParams !== undefined) {
        updates.push('preserve_query_params = ?')
        bindings.push(input.preserveQueryParams ? 1 : 0)
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
   * Delete a redirect
   */
  async delete(id: string): Promise<RedirectOperationResult> {
    try {
      const result = await this.db
        .prepare(`DELETE FROM redirects WHERE id = ?`)
        .bind(id)
        .run()

      if (result.meta.changes > 0) {
        // Invalidate cache after successful deletion
        invalidateRedirectCache()

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
      const conditions: string[] = []
      const bindings: any[] = []

      // Build WHERE clause from filters
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

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''

      // Build query with pagination
      const limit = filter?.limit ?? 50
      const offset = filter?.offset ?? 0

      const query = `
        SELECT
          id, source, destination, match_type, status_code, is_active,
          COALESCE(include_query_params, 0) as include_query_params,
          COALESCE(preserve_query_params, 0) as preserve_query_params,
          created_by, created_at, updated_at
        FROM redirects
        ${whereClause}
        ORDER BY created_at DESC
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
      const conditions: string[] = []
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

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''

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
            COALESCE(include_query_params, 0) as include_query_params,
            COALESCE(preserve_query_params, 0) as preserve_query_params,
            created_by, created_at, updated_at
          FROM redirects
          WHERE LOWER(source) = ? AND is_active = 1
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
        .prepare(`SELECT source, destination FROM redirects WHERE is_active = 1`)
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
    return {
      id: row.id as string,
      source: row.source as string,
      destination: row.destination as string,
      matchType: row.match_type as MatchType,
      statusCode: row.status_code as StatusCode,
      isActive: row.is_active === 1,
      includeQueryParams: (row.include_query_params ?? 0) === 1,
      preserveQueryParams: (row.preserve_query_params ?? 0) === 1,
      createdBy: row.created_by as string,
      createdAt: row.created_at as number,
      updatedAt: row.updated_at as number
    }
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
