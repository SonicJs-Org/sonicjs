/**
 * Telemetry Types
 *
 * Privacy-first telemetry types for SonicJS
 * No PII (Personally Identifiable Information) is collected
 */

export type TelemetryEvent =
  // Installation Events
  | 'installation_started'
  | 'installation_completed'
  | 'installation_failed'
  | 'setup_wizard_started'
  | 'setup_wizard_completed'
  | 'first_dev_server_start'

  // Runtime Events
  | 'dev_server_started'
  | 'dev_server_stopped'
  | 'admin_login'
  | 'plugin_activated'
  | 'plugin_deactivated'
  | 'collection_created'
  | 'content_created'

  // Admin UI Events
  | 'page_viewed'
  | 'feature_used'
  | 'error_occurred'
  | 'migration_run'
  | 'deployment_triggered'

  // Runtime snapshot (emitted on bootstrap)
  | 'project_snapshot'

export interface TelemetryProperties {
  // System Information (no PII)
  os?: 'darwin' | 'linux' | 'win32' | string
  nodeVersion?: string  // e.g., "18.0.0"
  packageManager?: 'npm' | 'yarn' | 'pnpm' | 'bun'

  // Installation Properties
  installationDuration?: number  // in milliseconds
  success?: boolean
  errorType?: string  // sanitized error type only, no messages

  // Runtime Properties
  sessionDuration?: number  // in milliseconds
  pluginsCount?: number  // count only, no plugin names
  collectionsCount?: number
  contentItemsCount?: number

  // Admin UI Properties
  route?: string  // route pattern only, no user data
  feature?: string  // generic feature name

  // Migration Properties
  migrationType?: 'initial' | 'update' | 'rollback'
  migrationSuccess?: boolean

  // Additional context (always anonymous)
  [key: string]: string | number | boolean | undefined
}

export interface TelemetryConfig {
  enabled: boolean
  host?: string  // Stats endpoint URL
  debug?: boolean
}

export interface TelemetryIdentity {
  installationId: string  // Anonymous UUID
  projectId?: string  // Anonymous project identifier
}
