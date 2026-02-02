/**
 * Cloudflare Bulk Redirects Service
 *
 * Handles synchronization of redirects to Cloudflare's Bulk Redirects feature.
 * This offloads redirect processing to the edge, improving performance.
 *
 * Required environment variables:
 * - CLOUDFLARE_API_TOKEN: API token with Account Filter Lists Edit + Account Rulesets Edit permissions
 * - CLOUDFLARE_ACCOUNT_ID: Cloudflare account ID (not zone ID)
 */

import type { Redirect, MatchType } from '../types'

const CLOUDFLARE_API_BASE = 'https://api.cloudflare.com/client/v4'
const LIST_NAME = 'sonicjs-redirects'
const RULESET_NAME = 'SonicJS Bulk Redirects'

export interface CloudflareConfig {
  apiToken: string
  accountId: string
}

export interface CloudflareSyncResult {
  success: boolean
  error?: string
  listId?: string
  ruleId?: string
  itemsAdded?: number
  itemsRemoved?: number
}

interface CloudflareListItem {
  redirect: {
    source_url: string
    target_url: string
    status_code: number
    preserve_query_string?: boolean
    include_subdomains?: boolean
    subpath_matching?: boolean
    preserve_path_suffix?: boolean
  }
}

interface CloudflareList {
  id: string
  name: string
  kind: string
}

interface CloudflareRuleset {
  id: string
  name: string
  phase: string
  rules: Array<{
    id: string
    expression: string
    action: string
  }>
}

/**
 * Check if Cloudflare integration is configured
 */
export function isConfigured(env: any): boolean {
  const token = env?.CLOUDFLARE_API_TOKEN
  const accountId = env?.CLOUDFLARE_ACCOUNT_ID
  return !!(token && accountId && token.length > 0 && accountId.length > 0)
}

/**
 * Get Cloudflare configuration from environment
 */
export function getConfig(env: any): CloudflareConfig | null {
  if (!isConfigured(env)) {
    return null
  }
  return {
    apiToken: env.CLOUDFLARE_API_TOKEN,
    accountId: env.CLOUDFLARE_ACCOUNT_ID
  }
}

/**
 * Check if a redirect is eligible for Cloudflare sync
 * Rules:
 * - matchType must be EXACT (0) or WILDCARD (1) - Cloudflare doesn't support regex
 * - statusCode must be 301, 302, 307, or 308 - Cloudflare doesn't support 410
 * - isActive must be true - don't sync disabled redirects
 */
export function isEligibleForSync(redirect: Redirect): boolean {
  const matchType = redirect.matchType as MatchType
  // EXACT = 0, WILDCARD = 1 are eligible; REGEX = 2 is not
  const validMatchType = matchType === 0 || matchType === 1
  const validStatusCode = [301, 302, 307, 308].includes(redirect.statusCode)
  return validMatchType && validStatusCode && redirect.isActive
}

/**
 * Make an authenticated request to the Cloudflare API
 */
async function cfFetch<T>(
  config: CloudflareConfig,
  path: string,
  options: RequestInit = {}
): Promise<{ success: boolean; result?: T; errors?: Array<{ message: string }> }> {
  const url = `${CLOUDFLARE_API_BASE}${path}`
  const headers = {
    'Authorization': `Bearer ${config.apiToken}`,
    'Content-Type': 'application/json',
    ...options.headers
  }

  try {
    const response = await fetch(url, {
      ...options,
      headers
    })

    const data = await response.json() as any

    if (!response.ok || !data.success) {
      console.error('[CloudflareBulk] API error:', data.errors)
      return {
        success: false,
        errors: data.errors || [{ message: `HTTP ${response.status}` }]
      }
    }

    return {
      success: true,
      result: data.result as T
    }
  } catch (error) {
    console.error('[CloudflareBulk] Fetch error:', error)
    return {
      success: false,
      errors: [{ message: error instanceof Error ? error.message : 'Network error' }]
    }
  }
}

/**
 * Get or create the redirect list named "sonicjs-redirects"
 */
export async function getOrCreateList(config: CloudflareConfig): Promise<{ success: boolean; listId?: string; error?: string }> {
  // First, try to find existing list
  const listPath = `/accounts/${config.accountId}/rules/lists`
  const listResponse = await cfFetch<CloudflareList[]>(config, listPath)

  if (listResponse.success && listResponse.result) {
    const existingList = listResponse.result.find(l => l.name === LIST_NAME && l.kind === 'redirect')
    if (existingList) {
      console.log('[CloudflareBulk] Found existing list:', existingList.id)
      return { success: true, listId: existingList.id }
    }
  }

  // Create new list
  const createResponse = await cfFetch<CloudflareList>(config, listPath, {
    method: 'POST',
    body: JSON.stringify({
      name: LIST_NAME,
      kind: 'redirect',
      description: 'SonicJS managed redirects - auto-synced from admin panel'
    })
  })

  if (createResponse.success && createResponse.result) {
    console.log('[CloudflareBulk] Created new list:', createResponse.result.id)
    return { success: true, listId: createResponse.result.id }
  }

  return {
    success: false,
    error: createResponse.errors?.[0]?.message || 'Failed to create redirect list'
  }
}

/**
 * Get or create the ruleset that references our list
 */
export async function getOrCreateRule(config: CloudflareConfig, _listId: string): Promise<{ success: boolean; ruleId?: string; error?: string }> {
  // Check for existing ruleset
  const rulesetPath = `/accounts/${config.accountId}/rulesets`
  const rulesetResponse = await cfFetch<CloudflareRuleset[]>(config, rulesetPath)

  if (rulesetResponse.success && rulesetResponse.result) {
    const existingRuleset = rulesetResponse.result.find(r => r.name === RULESET_NAME && r.phase === 'http_request_redirect')
    if (existingRuleset) {
      console.log('[CloudflareBulk] Found existing ruleset:', existingRuleset.id)
      // Return first rule ID if it exists
      const ruleId = existingRuleset.rules?.[0]?.id
      return { success: true, ruleId: ruleId || existingRuleset.id }
    }
  }

  // Create new ruleset with rule
  const createResponse = await cfFetch<CloudflareRuleset>(config, rulesetPath, {
    method: 'POST',
    body: JSON.stringify({
      name: RULESET_NAME,
      kind: 'root',
      phase: 'http_request_redirect',
      description: 'SonicJS bulk redirects - auto-synced from admin panel',
      rules: [{
        action: 'redirect',
        expression: `http.request.full_uri in $${LIST_NAME}`,
        description: 'Redirect from SonicJS managed list',
        action_parameters: {
          from_list: {
            name: LIST_NAME,
            key: 'http.request.full_uri'
          }
        }
      }]
    })
  })

  if (createResponse.success && createResponse.result) {
    console.log('[CloudflareBulk] Created new ruleset:', createResponse.result.id)
    const ruleId = createResponse.result.rules?.[0]?.id
    return { success: true, ruleId: ruleId || createResponse.result.id }
  }

  return {
    success: false,
    error: createResponse.errors?.[0]?.message || 'Failed to create redirect ruleset'
  }
}

/**
 * Convert a SonicJS redirect to Cloudflare list item format
 */
function redirectToCloudflareItem(redirect: Redirect): CloudflareListItem {
  // Build source URL - Cloudflare expects format like "example.com/path" (no protocol)
  let sourceUrl = redirect.source
  // Remove leading slash if present and no domain
  if (sourceUrl.startsWith('/') && !sourceUrl.includes('://')) {
    // For relative paths, we need a domain. This will be filled in by the middleware
    // that checks the host. For now, use a placeholder pattern.
    sourceUrl = `*${sourceUrl}`
  }

  return {
    redirect: {
      source_url: sourceUrl,
      target_url: redirect.destination,
      status_code: redirect.statusCode,
      preserve_query_string: redirect.preserveQueryString ?? false,
      include_subdomains: redirect.includeSubdomains ?? false,
      subpath_matching: redirect.subpathMatching ?? false,
      preserve_path_suffix: redirect.preservePathSuffix ?? true
    }
  }
}

/**
 * Sync a single redirect to Cloudflare
 * Used for real-time sync on create/update
 */
export async function syncRedirect(
  config: CloudflareConfig,
  listId: string,
  redirect: Redirect
): Promise<CloudflareSyncResult> {
  if (!isEligibleForSync(redirect)) {
    console.log('[CloudflareBulk] Redirect not eligible for sync:', redirect.id)
    return { success: true, itemsAdded: 0 }
  }

  const item = redirectToCloudflareItem(redirect)
  const path = `/accounts/${config.accountId}/rules/lists/${listId}/items`

  const response = await cfFetch<{ operation_id: string }>(config, path, {
    method: 'POST',
    body: JSON.stringify([item])
  })

  if (response.success) {
    console.log('[CloudflareBulk] Synced redirect:', redirect.source)
    return { success: true, listId, itemsAdded: 1 }
  }

  return {
    success: false,
    error: response.errors?.[0]?.message || 'Failed to sync redirect'
  }
}

/**
 * Remove a redirect from Cloudflare by source URL
 * Used for real-time sync on delete
 */
export async function removeRedirect(
  config: CloudflareConfig,
  listId: string,
  sourceUrl: string
): Promise<CloudflareSyncResult> {
  // First, get all items in the list to find the one with matching source
  const listPath = `/accounts/${config.accountId}/rules/lists/${listId}/items`
  const listResponse = await cfFetch<Array<{ id: string; redirect: { source_url: string } }>>(config, listPath)

  if (!listResponse.success || !listResponse.result) {
    return {
      success: false,
      error: 'Failed to fetch list items'
    }
  }

  // Find item with matching source URL
  // Handle both formats: with and without leading wildcard
  const normalizedSource = sourceUrl.startsWith('/') ? `*${sourceUrl}` : sourceUrl
  const item = listResponse.result.find(i =>
    i.redirect.source_url === sourceUrl ||
    i.redirect.source_url === normalizedSource
  )

  if (!item) {
    // Item doesn't exist in Cloudflare, nothing to remove
    console.log('[CloudflareBulk] Item not found in list:', sourceUrl)
    return { success: true, itemsRemoved: 0 }
  }

  // Delete the item
  const deleteResponse = await cfFetch(config, listPath, {
    method: 'DELETE',
    body: JSON.stringify({ items: [{ id: item.id }] })
  })

  if (deleteResponse.success) {
    console.log('[CloudflareBulk] Removed redirect:', sourceUrl)
    return { success: true, listId, itemsRemoved: 1 }
  }

  return {
    success: false,
    error: 'Failed to remove redirect from Cloudflare'
  }
}

/**
 * Sync all eligible redirects to Cloudflare (full sync)
 * Used for initial setup or manual sync
 */
export async function syncAll(
  config: CloudflareConfig,
  redirects: Redirect[]
): Promise<CloudflareSyncResult> {
  // Get or create the list
  const listResult = await getOrCreateList(config)
  if (!listResult.success || !listResult.listId) {
    return {
      success: false,
      error: listResult.error || 'Failed to get/create redirect list'
    }
  }

  const listId = listResult.listId

  // Get or create the rule
  const ruleResult = await getOrCreateRule(config, listId)
  if (!ruleResult.success) {
    return {
      success: false,
      error: ruleResult.error || 'Failed to get/create redirect rule',
      listId
    }
  }

  // Filter eligible redirects
  const eligibleRedirects = redirects.filter(isEligibleForSync)
  console.log(`[CloudflareBulk] Syncing ${eligibleRedirects.length} of ${redirects.length} redirects`)

  if (eligibleRedirects.length === 0) {
    return {
      success: true,
      listId,
      ruleId: ruleResult.ruleId,
      itemsAdded: 0
    }
  }

  // Clear existing items first (replace mode)
  const clearPath = `/accounts/${config.accountId}/rules/lists/${listId}/items`
  const existingItems = await cfFetch<Array<{ id: string }>>(config, clearPath)

  if (existingItems.success && existingItems.result && existingItems.result.length > 0) {
    const deleteBody = { items: existingItems.result.map(i => ({ id: i.id })) }
    await cfFetch(config, clearPath, {
      method: 'DELETE',
      body: JSON.stringify(deleteBody)
    })
    console.log(`[CloudflareBulk] Cleared ${existingItems.result.length} existing items`)
  }

  // Add all eligible redirects
  const items = eligibleRedirects.map(redirectToCloudflareItem)

  // Cloudflare has a limit of 1000 items per request, batch if needed
  const BATCH_SIZE = 1000
  let totalAdded = 0

  for (let i = 0; i < items.length; i += BATCH_SIZE) {
    const batch = items.slice(i, i + BATCH_SIZE)
    const addResponse = await cfFetch(config, clearPath, {
      method: 'POST',
      body: JSON.stringify(batch)
    })

    if (addResponse.success) {
      totalAdded += batch.length
      console.log(`[CloudflareBulk] Added batch of ${batch.length} items (${totalAdded}/${items.length})`)
    } else {
      console.error('[CloudflareBulk] Failed to add batch:', addResponse.errors)
      return {
        success: false,
        error: `Failed to sync batch: ${addResponse.errors?.[0]?.message}`,
        listId,
        itemsAdded: totalAdded
      }
    }
  }

  return {
    success: true,
    listId,
    ruleId: ruleResult.ruleId,
    itemsAdded: totalAdded
  }
}

/**
 * CloudflareBulkService class for dependency injection
 */
export class CloudflareBulkService {
  private config: CloudflareConfig | null
  private listId: string | null = null

  constructor(env: any) {
    this.config = getConfig(env)
  }

  isConfigured(): boolean {
    return this.config !== null
  }

  async ensureSetup(): Promise<{ success: boolean; error?: string }> {
    if (!this.config) {
      return { success: false, error: 'Cloudflare not configured' }
    }

    const listResult = await getOrCreateList(this.config)
    if (!listResult.success) {
      return { success: false, error: listResult.error }
    }

    this.listId = listResult.listId!

    const ruleResult = await getOrCreateRule(this.config, this.listId)
    if (!ruleResult.success) {
      return { success: false, error: ruleResult.error }
    }

    return { success: true }
  }

  async syncRedirect(redirect: Redirect): Promise<CloudflareSyncResult> {
    if (!this.config) {
      return { success: false, error: 'Cloudflare not configured' }
    }

    if (!this.listId) {
      const setup = await this.ensureSetup()
      if (!setup.success) {
        return { success: false, error: setup.error }
      }
    }

    return syncRedirect(this.config, this.listId!, redirect)
  }

  async removeRedirect(sourceUrl: string): Promise<CloudflareSyncResult> {
    if (!this.config) {
      return { success: false, error: 'Cloudflare not configured' }
    }

    if (!this.listId) {
      const setup = await this.ensureSetup()
      if (!setup.success) {
        return { success: false, error: setup.error }
      }
    }

    return removeRedirect(this.config, this.listId!, sourceUrl)
  }

  async syncAll(redirects: Redirect[]): Promise<CloudflareSyncResult> {
    if (!this.config) {
      return { success: false, error: 'Cloudflare not configured' }
    }

    return syncAll(this.config, redirects)
  }
}
