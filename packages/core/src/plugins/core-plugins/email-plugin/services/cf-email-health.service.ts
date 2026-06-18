import type { KVNamespace } from '@cloudflare/workers-types'

export type CfHealthStatus = 'ok' | 'error' | 'unconfigured'

export interface CfDestinationAddress {
  email: string
  verified: boolean
}

export interface CfAccountHealth {
  emailRoutingEnabled: boolean | null  // null = CF_ZONE_ID absent
  emailRoutingZone: string | null      // zone name e.g. 'sonicjs.com'; null if unconfigured
  destinations: CfDestinationAddress[] // empty if CF_ACCOUNT_ID absent
  checkedAt: number                    // unix ms
  status: CfHealthStatus
  // 'ok'           = credentials present, both API calls succeeded
  // 'error'        = credentials present, at least one API call failed
  // 'unconfigured' = required credential absent
}

// CF API response shapes
interface CfEmailRoutingResult {
  name: string
  enabled: boolean
}

interface CfEmailAddressResult {
  email: string
  verified: string | null // ISO timestamp string if verified; null if not
}

interface CfApiResponse<T> {
  success: boolean
  result: T
}

const CF_API = 'https://api.cloudflare.com/client/v4'
const CACHE_TTL = 60 // seconds

export class CfEmailHealthService {
  constructor(
    private readonly apiToken: string | undefined,
    private readonly accountId: string | undefined,
    private readonly zoneId: string | undefined,
    private readonly kv: KVNamespace | undefined,
  ) {}

  async getHealth(): Promise<CfAccountHealth> {
    try {
      // Unconfigured: can't call any endpoint without token + accountId
      if (!this.apiToken || !this.accountId) {
        return {
          status: 'unconfigured',
          emailRoutingEnabled: null,
          emailRoutingZone: null,
          destinations: [],
          checkedAt: Date.now(),
        }
      }

      const cacheKey = `cf-email-health:${this.accountId}`

      // Try KV cache first
      if (this.kv) {
        try {
          const cached = await this.kv.get(cacheKey, 'json') as CfAccountHealth | null
          if (cached) return cached
        } catch {
          // KV read failed — fall through to live fetch
        }
      }

      // Fetch both endpoints in parallel where credentials allow
      const [routingResult, destinationsResult] = await Promise.all([
        this.zoneId ? this.fetchRouting(this.zoneId) : Promise.resolve(null),
        this.fetchDestinations(this.accountId),
      ])

      const anyError =
        (this.zoneId && routingResult === 'error') ||
        destinationsResult === 'error'

      const health: CfAccountHealth = {
        status: anyError ? 'error' : 'ok',
        emailRoutingEnabled: routingResult === null || routingResult === 'error'
          ? null
          : routingResult.enabled,
        emailRoutingZone: routingResult === null || routingResult === 'error'
          ? null
          : routingResult.name,
        destinations: destinationsResult === 'error'
          ? []
          : destinationsResult.map((a) => ({ email: a.email, verified: !!a.verified })),
        checkedAt: Date.now(),
      }

      // Cache the result
      if (this.kv) {
        try {
          await this.kv.put(cacheKey, JSON.stringify(health), { expirationTtl: CACHE_TTL })
        } catch {
          // KV write failed — non-fatal
        }
      }

      return health
    } catch (err) {
      /* v8 ignore next 8 -- outer defensive catch; fetchRouting/fetchDestinations each have their own try-catch so this only fires on truly unexpected runtime errors */
      console.error('[cf-email-health] getHealth() threw unexpectedly', err)
      return {
        status: 'error',
        emailRoutingEnabled: null,
        emailRoutingZone: null,
        destinations: [],
        checkedAt: Date.now(),
      }
    }
  }

  private async fetchRouting(zoneId: string): Promise<CfEmailRoutingResult | 'error'> {
    try {
      const response = await fetch(`${CF_API}/zones/${zoneId}/email/routing`, {
        headers: { 'Authorization': `Bearer ${this.apiToken}` },
      })
      if (!response.ok) {
        console.error(`[cf-email-health] routing check HTTP ${response.status} for zone ${zoneId}`)
        return 'error'
      }
      const data = await response.json() as CfApiResponse<CfEmailRoutingResult>
      if (!data.success) {
        console.error(`[cf-email-health] routing check success:false for zone ${zoneId}`, JSON.stringify(data))
        return 'error'
      }
      return data.result
    } catch (err) {
      console.error(`[cf-email-health] routing check threw for zone ${zoneId}`, err)
      return 'error'
    }
  }

  private async fetchDestinations(accountId: string): Promise<CfEmailAddressResult[] | 'error'> {
    try {
      const response = await fetch(
        `${CF_API}/accounts/${accountId}/email/routing/addresses`,
        { headers: { 'Authorization': `Bearer ${this.apiToken}` } },
      )
      if (!response.ok) {
        console.error(`[cf-email-health] destinations check HTTP ${response.status} for account ${accountId}`)
        return 'error'
      }
      const data = await response.json() as CfApiResponse<CfEmailAddressResult[]>
      if (!data.success) {
        console.error(`[cf-email-health] destinations check success:false for account ${accountId}`, JSON.stringify(data))
        return 'error'
      }
      return data.result ?? []
    } catch (err) {
      console.error(`[cf-email-health] destinations check threw for account ${accountId}`, err)
      return 'error'
    }
  }
}
