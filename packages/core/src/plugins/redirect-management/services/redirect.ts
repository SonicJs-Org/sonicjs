import manifest from '../manifest.json'
import type { RedirectSettings, Redirect, CreateRedirectInput, UpdateRedirectInput, RedirectFilter, RedirectOperationResult, MatchType, StatusCode, ValidatedRedirectRow } from '../types'
import type { D1Database } from '@cloudflare/workers-types'
import { normalizeUrl } from '../utils/url-normalizer'
import { validateRedirect, type ValidationResult } from '../utils/validator'
import { invalidateRedirectCache } from '../middleware/redirect'
import { CloudflareBulkService, isEligibleForSync } from './cloudflare-bulk'
import { DocumentsService } from '../../../services/documents'
import type { QueryableField } from '../../../schemas/document'
import { nanoid } from 'nanoid'

const TYPE_ID = 'redirect'
const TENANT = 'default'

export const REDIRECT_QUERYABLE_FIELDS: QueryableField[] = [
  { name: 'source',      kind: 'scalar', type: 'text',    column: 'q_redir_source' },
  { name: 'destination', kind: 'scalar', type: 'text',    column: 'q_redir_destination' },
  { name: 'statusCode',  kind: 'scalar', type: 'integer', column: 'q_redir_status_code' },
  { name: 'isActive',    kind: 'scalar', type: 'integer', column: 'q_redir_is_active' },
  { name: 'matchType',   kind: 'scalar', type: 'integer', column: 'q_redir_match_type' },
]

function docToRedirect(row: any): Redirect {
  const data = typeof row.data === 'string' ? JSON.parse(row.data) : (row.data ?? {})
  return {
    id: row.root_id ?? row.id,
    source: data.source ?? '',
    destination: data.destination ?? '',
    matchType: (data.matchType ?? 0) as MatchType,
    statusCode: (data.statusCode ?? 301) as StatusCode,
    isActive: data.isActive === true || data.isActive === 1,
    preserveQueryString: data.preserveQueryString ?? false,
    includeSubdomains: data.includeSubdomains ?? false,
    subpathMatching: data.subpathMatching ?? false,
    preservePathSuffix: data.preservePathSuffix ?? true,
    sourcePlugin: data.sourcePlugin ?? null,
    createdBy: row.created_by ?? '',
    createdAt: (row.created_at ?? 0) * 1000,
    updatedAt: (row.updated_at ?? 0) * 1000,
    updatedBy: row.updated_by ?? undefined,
    hitCount: data.hitCount ?? 0,
    lastHitAt: data.lastHitAt ?? null,
    createdByName: row.created_by_name ?? undefined,
    updatedByName: row.updated_by_name ?? undefined,
  }
}

function buildListConditions(filter?: RedirectFilter): { conditions: string[]; params: (string | number)[] } {
  const conditions = [
    'type_id = ?', 'tenant_id = ?', 'is_current_draft = 1', 'deleted_at IS NULL',
  ]
  const params: (string | number)[] = [TYPE_ID, TENANT]

  if (filter?.isActive !== undefined) {
    conditions.push('q_redir_is_active = ?')
    params.push(filter.isActive ? 1 : 0)
  }
  if (filter?.statusCode !== undefined) {
    conditions.push('q_redir_status_code = ?')
    params.push(filter.statusCode)
  }
  if (filter?.matchType !== undefined) {
    conditions.push('q_redir_match_type = ?')
    params.push(filter.matchType)
  }
  if (filter?.search) {
    conditions.push('(q_redir_source LIKE ? OR q_redir_destination LIKE ?)')
    const pat = `%${filter.search}%`
    params.push(pat, pat)
  }
  if (filter?.sourcePlugin !== undefined) {
    if (filter.sourcePlugin === null) {
      conditions.push("json_extract(data, '$.sourcePlugin') IS NULL")
    } else {
      conditions.push("json_extract(data, '$.sourcePlugin') = ?")
      params.push(filter.sourcePlugin)
    }
  }

  return { conditions, params }
}

export class RedirectService {
  private cloudflareService: CloudflareBulkService | null = null

  constructor(private db: D1Database, private env?: any) {
    if (env) {
      this.cloudflareService = new CloudflareBulkService(env)
    }
  }

  private getDocService(): DocumentsService {
    return new DocumentsService(this.db, {
      queryableFields: REDIRECT_QUERYABLE_FIELDS,
      maxVersionsPerRoot: 1,
      tenantId: TENANT,
    })
  }

  async getSettings(): Promise<{ status: string; data: RedirectSettings }> {
    try {
      const record = await this.db
        .prepare(`SELECT settings, status FROM plugins WHERE id = ?`)
        .bind(manifest.id)
        .first()

      if (!record) {
        return { status: 'inactive', data: this.getDefaultSettings() }
      }

      return {
        status: (record?.status as string) || 'inactive',
        data: record?.settings ? JSON.parse(record.settings as string) : this.getDefaultSettings()
      }
    } catch {
      return { status: 'inactive', data: this.getDefaultSettings() }
    }
  }

  getDefaultSettings(): RedirectSettings {
    return { enabled: true, autoOffloadEnabled: false }
  }

  private async shouldSyncToCloudflare(): Promise<boolean> {
    if (!this.cloudflareService?.isConfigured()) return false
    const { data: settings } = await this.getSettings()
    return settings.autoOffloadEnabled === true
  }

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
      console.error('[RedirectService] Cloudflare sync error:', error)
    }
  }

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

  async create(input: CreateRedirectInput, userId: string): Promise<RedirectOperationResult> {
    try {
      const matchType = input.matchType ?? 0
      const statusCode = input.statusCode ?? 301
      const isActive = input.isActive ?? true
      const preserveQueryString = input.preserveQueryString ?? false
      const includeSubdomains = input.includeSubdomains ?? false
      const subpathMatching = input.subpathMatching ?? false
      const preservePathSuffix = input.preservePathSuffix ?? true
      const sourcePlugin = input.sourcePlugin ?? null

      const normalizedSource = normalizeUrl(input.source)
      const existingMap = await this.getAllSourceDestinationMap()

      if (existingMap.has(normalizedSource)) {
        return { success: false, redirect: undefined, error: 'A redirect with this source URL already exists', warning: undefined }
      }

      const validation = validateRedirect(input.source, input.destination, existingMap)
      if (!validation.isValid) {
        return { success: false, redirect: undefined, error: validation.error, warning: undefined }
      }

      const svc = this.getDocService()
      const doc = await svc.create({
        typeId: TYPE_ID,
        title: normalizedSource,
        publishOnCreate: true,
        tenantId: TENANT,
        locale: 'default',
        parentRootId: '',
        sortOrder: 0,
        visible: true,
        metadata: {},
        data: {
          source: normalizedSource,
          destination: input.destination,
          statusCode,
          matchType,
          isActive,
          preserveQueryString,
          includeSubdomains,
          subpathMatching,
          preservePathSuffix,
          sourcePlugin,
          hitCount: 0,
          lastHitAt: null,
        },
      }, userId)

      const redirect = docToRedirect({ ...doc, data: doc.data })
      invalidateRedirectCache()

      this.syncToCloudflareIfEnabled(redirect)

      return { success: true, redirect, error: undefined, warning: validation.warning }
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

  async batchCreate(rows: ValidatedRedirectRow[], userId: string): Promise<number> {
    const now = Math.floor(Date.now() / 1000)

    const statements = rows.map(r => {
      const id = nanoid()
      const data = JSON.stringify({
        source: r.source,
        destination: r.destination,
        statusCode: r.statusCode,
        matchType: r.matchType,
        isActive: r.isActive,
        preserveQueryString: r.preserveQueryString ?? false,
        includeSubdomains: r.includeSubdomains ?? false,
        subpathMatching: r.subpathMatching ?? false,
        preservePathSuffix: r.preservePathSuffix ?? true,
        sourcePlugin: null,
        hitCount: 0,
        lastHitAt: null,
      })

      return this.db.prepare(
        `INSERT INTO documents (
          id, root_id, type_id, type_version, version_of_id, version_number,
          is_current_draft, is_published, status, parent_root_id, slug, path, title, zone,
          sort_order, visible, published_at, scheduled_at, expires_at, deleted_at,
          tenant_id, locale, translation_group_id, data, metadata,
          owner_id, created_by, updated_by, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(
        id, id, TYPE_ID, 1, null, 1,
        1, 1, 'published', '', null, null, r.source, null,
        0, 1, now, null, null, null,
        TENANT, 'default', '', data, '{}',
        null, userId, userId, now, now
      )
    })

    await this.db.batch(statements)
    invalidateRedirectCache()
    return rows.length
  }

  async getById(id: string): Promise<Redirect | null> {
    try {
      const row = await this.db.prepare(`
        SELECT d.*,
          creator.first_name || ' ' || creator.last_name as created_by_name,
          updater.first_name || ' ' || updater.last_name as updated_by_name
        FROM documents d
        LEFT JOIN auth_user creator ON d.created_by = creator.id
        LEFT JOIN auth_user updater ON d.updated_by = updater.id
        WHERE d.root_id = ? AND d.tenant_id = ? AND d.is_current_draft = 1 AND d.deleted_at IS NULL
      `).bind(id, TENANT).first()

      if (!row) return null
      return docToRedirect(row)
    } catch (error) {
      console.error('Error getting redirect by ID:', error)
      return null
    }
  }

  async update(id: string, input: UpdateRedirectInput, userId?: string): Promise<RedirectOperationResult> {
    try {
      const existing = await this.getById(id)
      if (!existing) {
        return { success: false, redirect: undefined, error: 'Redirect not found', warning: undefined }
      }

      let validation: ValidationResult | undefined
      if (input.source !== undefined || input.destination !== undefined) {
        const newSource = input.source ?? existing.source
        const newDestination = input.destination ?? existing.destination
        const existingMap = await this.getAllSourceDestinationMap()
        existingMap.delete(normalizeUrl(existing.source))
        validation = validateRedirect(newSource, newDestination, existingMap)
        if (!validation.isValid) {
          return { success: false, redirect: undefined, error: validation.error, warning: undefined }
        }
      }

      const newData = {
        source: input.source !== undefined ? normalizeUrl(input.source) : existing.source,
        destination: input.destination ?? existing.destination,
        statusCode: input.statusCode ?? existing.statusCode,
        matchType: input.matchType ?? existing.matchType,
        isActive: input.isActive ?? existing.isActive,
        preserveQueryString: input.preserveQueryString ?? existing.preserveQueryString,
        includeSubdomains: input.includeSubdomains ?? existing.includeSubdomains,
        subpathMatching: input.subpathMatching ?? existing.subpathMatching,
        preservePathSuffix: input.preservePathSuffix ?? existing.preservePathSuffix,
        sourcePlugin: existing.sourcePlugin ?? null,
        hitCount: existing.hitCount ?? 0,
        lastHitAt: existing.lastHitAt ?? null,
      }

      const now = Math.floor(Date.now() / 1000)

      await this.db.prepare(`
        UPDATE documents
        SET data = ?, title = ?, updated_at = ?, updated_by = ?
        WHERE root_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
      `).bind(JSON.stringify(newData), newData.source, now, userId ?? null, id, TENANT).run()

      const updated = await this.getById(id)
      invalidateRedirectCache()

      if (updated) {
        this.syncToCloudflareIfEnabled(updated)
      }

      return { success: true, redirect: updated!, error: undefined, warning: validation?.warning }
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

  async delete(id: string): Promise<RedirectOperationResult> {
    try {
      const redirect = await this.getById(id)
      const now = Math.floor(Date.now() / 1000)

      const result = await this.db.prepare(`
        UPDATE documents SET deleted_at = ?
        WHERE root_id = ? AND tenant_id = ? AND deleted_at IS NULL
      `).bind(now, id, TENANT).run()

      if (result.meta.changes > 0) {
        invalidateRedirectCache()
        if (redirect) {
          this.removeFromCloudflareIfEnabled(redirect.source)
        }
        return { success: true, redirect: undefined, error: undefined, warning: undefined }
      } else {
        return { success: false, redirect: undefined, error: 'Redirect not found', warning: undefined }
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

  async list(filter?: RedirectFilter): Promise<Redirect[]> {
    try {
      const { conditions, params } = buildListConditions(filter)
      const limit = filter?.limit ?? 50
      const offset = filter?.offset ?? 0

      const { results } = await this.db.prepare(`
        SELECT d.*,
          creator.first_name || ' ' || creator.last_name as created_by_name,
          updater.first_name || ' ' || updater.last_name as updated_by_name
        FROM documents d
        LEFT JOIN auth_user creator ON d.created_by = creator.id
        LEFT JOIN auth_user updater ON d.updated_by = updater.id
        WHERE ${conditions.join(' AND ')}
        ORDER BY d.created_at DESC LIMIT ? OFFSET ?
      `).bind(...params, limit, offset).all()

      return (results ?? []).map(docToRedirect)
    } catch (error) {
      console.error('Error listing redirects:', error)
      return []
    }
  }

  async count(filter?: RedirectFilter): Promise<number> {
    try {
      const { conditions, params } = buildListConditions(filter)

      const result = await this.db.prepare(`
        SELECT COUNT(*) as count FROM documents
        WHERE ${conditions.join(' AND ')}
      `).bind(...params).first()

      return (result?.count as number) ?? 0
    } catch (error) {
      console.error('Error counting redirects:', error)
      return 0
    }
  }

  async lookupBySource(normalizedSource: string): Promise<Redirect | null> {
    try {
      const row = await this.db.prepare(`
        SELECT * FROM documents
        WHERE type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
          AND LOWER(q_redir_source) = ? AND q_redir_is_active = 1
        LIMIT 1
      `).bind(TYPE_ID, TENANT, normalizedSource.toLowerCase()).first()

      if (!row) return null
      return docToRedirect(row)
    } catch (error) {
      console.error('Error looking up redirect by source:', error)
      return null
    }
  }

  async getAllSourceDestinationMap(): Promise<Map<string, string>> {
    try {
      const { results } = await this.db.prepare(`
        SELECT q_redir_source as source, q_redir_destination as destination
        FROM documents
        WHERE type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
          AND q_redir_is_active = 1
      `).bind(TYPE_ID, TENANT).all()

      const map = new Map<string, string>()
      for (const row of results) {
        const normalizedSource = normalizeUrl(row.source as string)
        map.set(normalizedSource, row.destination as string)
      }
      return map
    } catch (error) {
      console.error('Error getting source-destination map:', error)
      return new Map()
    }
  }

  async syncAllToCloudflare(): Promise<{ success: boolean; itemsAdded?: number; error?: string }> {
    if (!this.cloudflareService?.isConfigured()) {
      return { success: false, error: 'Cloudflare not configured. Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID environment variables.' }
    }

    try {
      const redirects = await this.list({ isActive: true, limit: 10000 })
      return this.cloudflareService.syncAll(redirects)
    } catch (error) {
      console.error('[RedirectService] Full Cloudflare sync error:', error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to sync to Cloudflare'
      }
    }
  }

  isCloudflareConfigured(): boolean {
    return this.cloudflareService?.isConfigured() ?? false
  }

  async saveSettings(settings: RedirectSettings): Promise<void> {
    try {
      const existing = await this.db
        .prepare(`SELECT id FROM plugins WHERE id = ?`)
        .bind(manifest.id)
        .first()

      if (existing) {
        await this.db
          .prepare(`UPDATE plugins SET settings = ?, last_updated = ? WHERE id = ?`)
          .bind(JSON.stringify(settings), Date.now(), manifest.id)
          .run()
      } else {
        await this.db
          .prepare(`
            INSERT INTO plugins (id, name, display_name, description, version, author, category, status, settings, installed_at, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'inactive', ?, ?, ?)
          `)
          .bind(
            manifest.id, manifest.id, manifest.name,
            manifest.description || '', manifest.version || '1.0.0',
            manifest.author || 'Unknown', manifest.category || 'other',
            JSON.stringify(settings), Date.now(), Date.now()
          )
          .run()
      }
    } catch (error) {
      throw new Error(`Failed to save redirect management settings: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  async install(): Promise<void> {
    console.log('Redirect management plugin installed (document-model backed)')
  }

  async activate(): Promise<void> {
    console.log('Redirect management plugin activated')
  }

  async deactivate(): Promise<void> {
    console.log('Redirect management plugin deactivated')
  }

  async uninstall(): Promise<void> {
    console.log('Redirect management plugin uninstalled')
  }
}
