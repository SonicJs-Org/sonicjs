/**
 * Telemetry Service
 *
 * Privacy-first telemetry service using custom SonicJS stats endpoint
 * - No PII collection
 * - Opt-out by default
 * - Silent failures (never blocks app)
 */

import type { TelemetryEvent, TelemetryProperties, TelemetryConfig, TelemetryIdentity } from '../types/telemetry'
import { getTelemetryConfig } from '../utils/telemetry-config'
import { generateInstallationId, generateProjectId, sanitizeErrorMessage, sanitizeRoute } from '../utils/telemetry-id'

/**
 * TelemetryService class
 *
 * Handles all telemetry tracking in a privacy-conscious way
 */
export class TelemetryService {
  private config: TelemetryConfig
  private identity: TelemetryIdentity | null = null
  private enabled: boolean = true
  private eventQueue: Array<{ event: TelemetryEvent; properties?: TelemetryProperties }> = []
  private isInitialized: boolean = false

  constructor(config?: Partial<TelemetryConfig>) {
    this.config = {
      ...getTelemetryConfig(),
      ...config
    }
    this.enabled = this.config.enabled
  }

  /**
   * Initialize the telemetry service
   */
  async initialize(identity: TelemetryIdentity): Promise<void> {
    if (!this.enabled) {
      if (this.config.debug) {
        console.log('[Telemetry] Disabled via configuration')
      }
      return
    }

    try {
      this.identity = identity

      if (this.config.debug) {
        console.log('[Telemetry] Initialized with installation ID:', identity.installationId)
      }

      this.isInitialized = true

      // Flush any queued events
      await this.flushQueue()

    } catch (error) {
      // Silent fail - telemetry should never break the app
      if (this.config.debug) {
        console.error('[Telemetry] Initialization failed:', error)
      }
      this.enabled = false
    }
  }

  /**
   * Track a telemetry event
   */
  async track(event: TelemetryEvent, properties?: TelemetryProperties): Promise<void> {
    if (!this.enabled) return

    try {
      // Sanitize properties
      const sanitizedProps = this.sanitizeProperties(properties)

      // Add standard properties
      const enrichedProps = {
        ...sanitizedProps,
        timestamp: new Date().toISOString(),
        version: this.getVersion()
      }

      // If not initialized, queue the event
      if (!this.isInitialized) {
        this.eventQueue.push({ event, properties: enrichedProps })
        if (this.config.debug) {
          console.log('[Telemetry] Queued event:', event, enrichedProps)
        }
        return
      }

      // Send to custom SonicJS stats endpoint
      if (this.identity && this.config.host) {
        const payload = {
          data: {
            installation_id: this.identity.installationId,
            event_type: event,
            properties: enrichedProps,
            timestamp: enrichedProps.timestamp
          }
        }

        // Fire and forget - don't block on response
        fetch(`${this.config.host}/v1/events`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        }).catch(() => {}) // Silent fail

        if (this.config.debug) {
          console.log('[Telemetry] Tracked event:', event, enrichedProps)
        }
      } else if (this.config.debug) {
        console.log('[Telemetry] Event (no endpoint):', event, enrichedProps)
      }

    } catch (error) {
      // Silent fail
      if (this.config.debug) {
        console.error('[Telemetry] Failed to track event:', error)
      }
    }
  }

  /**
   * Track installation started
   */
  async trackInstallationStarted(properties?: TelemetryProperties): Promise<void> {
    await this.track('installation_started', properties)
  }

  /**
   * Track installation completed
   */
  async trackInstallationCompleted(properties?: TelemetryProperties): Promise<void> {
    await this.track('installation_completed', properties)
  }

  /**
   * Track installation failed
   */
  async trackInstallationFailed(error: Error | string, properties?: TelemetryProperties): Promise<void> {
    await this.track('installation_failed', {
      ...properties,
      errorType: sanitizeErrorMessage(error)
    })
  }

  /**
   * Track dev server started
   */
  async trackDevServerStarted(properties?: TelemetryProperties): Promise<void> {
    await this.track('dev_server_started', properties)
  }

  /**
   * Track page view in admin UI
   */
  async trackPageView(route: string, properties?: TelemetryProperties): Promise<void> {
    await this.track('page_viewed', {
      ...properties,
      route: sanitizeRoute(route)
    })
  }

  /**
   * Track error (sanitized)
   */
  async trackError(error: Error | string, properties?: TelemetryProperties): Promise<void> {
    await this.track('error_occurred', {
      ...properties,
      errorType: sanitizeErrorMessage(error)
    })
  }

  /**
   * Track plugin activation
   */
  async trackPluginActivated(properties?: TelemetryProperties): Promise<void> {
    await this.track('plugin_activated', properties)
  }

  /**
   * Track migration run
   */
  async trackMigrationRun(properties?: TelemetryProperties): Promise<void> {
    await this.track('migration_run', properties)
  }

  /**
   * Track project snapshot — fired on bootstrap to capture runtime project shape.
   * Arrays serialized as JSON strings (sanitizeProperties strips objects/arrays).
   */
  async trackProjectSnapshot(data: {
    installation_id: string
    collection_names: string[]
    collection_counts: Record<string, number>
    active_plugins: string[]
    field_type_histogram: Record<string, number>
    doc_total: number
    sonicjs_version: string
  }): Promise<void> {
    // Temporarily set identity so track() sends the event even if not initialized
    if (!this.identity) {
      this.identity = { installationId: data.installation_id }
      this.isInitialized = true
    }
    await this.track('project_snapshot', {
      installation_id: data.installation_id,
      collection_names: JSON.stringify(data.collection_names),
      collection_counts: JSON.stringify(data.collection_counts),
      active_plugins: JSON.stringify(data.active_plugins),
      field_type_histogram: JSON.stringify(data.field_type_histogram),
      doc_total: data.doc_total,
      sonicjs_version: data.sonicjs_version,
    })
  }

  /**
   * Flush queued events
   */
  private async flushQueue(): Promise<void> {
    if (this.eventQueue.length === 0) return

    const queue = [...this.eventQueue]
    this.eventQueue = []

    for (const { event, properties } of queue) {
      await this.track(event, properties)
    }
  }

  /**
   * Sanitize properties to ensure no PII
   */
  private sanitizeProperties(properties?: TelemetryProperties): TelemetryProperties {
    if (!properties) return {}

    const sanitized: TelemetryProperties = {}

    for (const [key, value] of Object.entries(properties)) {
      // Skip undefined values
      if (value === undefined) continue

      // Sanitize routes
      if (key === 'route' && typeof value === 'string') {
        sanitized[key] = sanitizeRoute(value)
        continue
      }

      // Sanitize error messages
      if (key.toLowerCase().includes('error') && typeof value === 'string') {
        sanitized[key] = sanitizeErrorMessage(value)
        continue
      }

      // Only allow specific types
      if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        sanitized[key] = value
      }
    }

    return sanitized
  }

  /**
   * Get SonicJS version
   */
  private getVersion(): string {
    try {
      // Safe environment access for Cloudflare Workers compatibility
      if (typeof process !== 'undefined' && process.env) {
        return process.env.SONICJS_VERSION || '2.0.0'
      }
      return '2.0.0'
    } catch {
      return 'unknown'
    }
  }

  /**
   * Shutdown the telemetry service (no-op for fetch-based telemetry)
   */
  async shutdown(): Promise<void> {
    // No-op - fetch requests are fire and forget
  }

  /**
   * Enable telemetry
   */
  enable(): void {
    this.enabled = true
  }

  /**
   * Disable telemetry
   */
  disable(): void {
    this.enabled = false
  }

  /**
   * Check if telemetry is enabled
   */
  isEnabled(): boolean {
    return this.enabled
  }
}

// Singleton instance
let telemetryInstance: TelemetryService | null = null

/**
 * Get the telemetry service instance
 */
export function getTelemetryService(config?: Partial<TelemetryConfig>): TelemetryService {
  if (!telemetryInstance) {
    telemetryInstance = new TelemetryService(config)
  }
  return telemetryInstance
}

/**
 * Initialize telemetry service
 */
export async function initTelemetry(identity: TelemetryIdentity, config?: Partial<TelemetryConfig>): Promise<TelemetryService> {
  const service = getTelemetryService(config)
  await service.initialize(identity)
  return service
}

/**
 * Create a new installation identity
 */
export function createInstallationIdentity(projectName?: string): TelemetryIdentity {
  const installationId = generateInstallationId()
  const identity: TelemetryIdentity = { installationId }

  if (projectName) {
    // Generate anonymous project ID
    identity.projectId = generateProjectId(projectName)
  }

  return identity
}
