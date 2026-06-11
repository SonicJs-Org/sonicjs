/**
 * Services Module Exports
 *
 * Core business logic services for SonicJS
 */

// Collection Management
export {
  loadCollectionConfigs,
  loadCollectionConfig,
  getAvailableCollectionNames,
  validateCollectionConfig,
  registerCollections,
} from './collection-loader'

// Collection Registry (code-only, in-memory)
export {
  CollectionRegistry,
  getCollectionRegistry,
  resetCollectionRegistry,
  collectionRecordToRow,
} from './collection-registry'
export type { CollectionRecord, CollectionRowShape } from './collection-registry'

// Database Migrations
export { MigrationService } from './migrations'
export type { Migration, MigrationStatus } from './migrations'

// Logging
export { Logger, getLogger, initLogger } from './logger'
export type { LogLevel, LogCategory, LogEntry, LogFilter } from './logger'

// Plugin Services
export { PluginService } from './plugin-service'
export { PluginBootstrapService } from './plugin-bootstrap'
export type { CorePlugin } from './plugin-bootstrap'

// Cache Service
export { CacheService, getCacheService, CACHE_CONFIGS } from './cache'
export type { CacheConfig } from './cache'

// Settings Service
export { SettingsService } from './settings'
export type { GeneralSettings, SecuritySettings } from './settings'

// Telemetry Service
export {
  TelemetryService,
  getTelemetryService,
  initTelemetry,
  createInstallationIdentity
} from './telemetry-service'

// Route Metadata (auto-discovery for API reference)
export {
  buildRouteList,
  setAppInstance,
  getAppInstance,
  CATEGORY_INFO
} from './route-metadata'
export type { RouteMetadata } from './route-metadata'
