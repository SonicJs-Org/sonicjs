/**
 * Plugins Module Exports
 *
 * Plugin system and SDK for SonicJS
 */

// Hook System
export { HookSystemImpl, ScopedHookSystem, HookUtils } from './hook-system'

// Plugin Registry
export { PluginRegistryImpl } from './plugin-registry'

// Plugin Manager
export { PluginManager } from './plugin-manager'

// Plugin Validator
export { PluginValidator } from './plugin-validator'

// Route mounting primitive
export {
  registerPluginRoutes,
  mountPlugin,
  PluginRegisterMustBeSyncError,
} from './mount'
export type { MountResult, MountedRoute, RegisterPluginRoutesOptions } from './mount'

// Typed hook catalog + facade
export {
  HOOK_EVENT_NAMES,
  isKnownHookEvent,
  isLegacyHookEvent,
  resolveHookEventName,
  LEGACY_EVENT_ALIASES,
} from './hooks/catalog'
export type {
  HookEventName,
  HookEventPayloads,
  HookPayload,
  HookActor,
  ContentEventPayload,
  AuthRegistrationCompletedPayload,
  AuthPasswordResetRequestedPayload,
  AuthPasswordResetCompletedPayload,
  AuthMagicLinkConsumedPayload,
  AuthOtpVerifiedPayload,
  LegacyHookEventName,
  LegacyHookEventPayloads,
} from './hooks/catalog'
export { createTypedHooks } from './hooks/typed-hooks'
export type {
  TypedHooks,
  TypedHookHandler,
  TypedHookContext,
  HookSystemLike,
  SubscribableEvent,
  PayloadForEvent,
} from './hooks/typed-hooks'
export {
  setHookSystem,
  getHookSystem,
  hasHookSystem,
  resetHookSystem,
  getTypedHooks,
} from './hooks/hook-system-singleton'

// Two-phase wiring
export { wireRegisteredPlugins, createPluginWirer } from './wire'
export type { WirablePlugin, WirableHook, PluginBootContext, WireResult } from './wire'

// Capabilities
export {
  FIXED_CAPABILITIES,
  isKnownCapability,
  SonicCapabilityError,
  hasCapability,
  assertCapability,
  validateCapabilities,
  normalizeCapability,
  normalizeCapabilities,
  CAPABILITY_RENAMES,
  createCapabilityContext,
} from './capabilities'
export type {
  Capability,
  FixedCapability,
  DbCapability,
  CapabilityProviders,
  CapabilityContext,
  PluginCapabilityContext,
} from './capabilities'

// Service singletons
export { createServiceSingleton } from './singletons/service-singleton'
export type { ServiceSingleton } from './singletons/service-singleton'

// v3 authoring API
export { definePlugin, isDefinedPlugin } from './sdk/define-plugin'
export type { DefinePluginInput, DefinedPlugin, DefinedPluginContext, DeclarativeHooks } from './sdk/define-plugin'

// Single-chokepoint registration
export { registerPlugins, RegisterPluginsError } from './sdk/register-plugins'
export type {
  RegisterablePlugin,
  RegisterPluginsHostContext,
  RegisterPluginsErrorReason,
  PluginsRegistry,
  RegistryEntry,
} from './sdk/register-plugins'

// Schema-driven settings
export {
  parseConfigSchema,
  renderSchemaFields,
  parseFormDataToSettings,
  applySchemaDefaults,
} from './sdk/config-schema'
export type {
  ConfigSchema,
  ConfigSchemaField,
  StringField,
  NumberField,
  BooleanField,
  SelectField,
  ParsedField,
  SettingsFor,
} from './sdk/config-schema'

// Cron surface
export {
  collectCrons,
  collectCronSchedules,
  dispatchCronTick,
  createScheduledHandler,
} from './cron'
export type {
  CronDeclaration,
  CronTickEvent,
  CronContext,
  CronablePlugin,
  CollectedCron,
  CronDispatchResult,
  ScheduledControllerLike,
  ExecutionContextLike,
  CreateScheduledHandlerOptions,
} from './cron'

// Core Plugins
export { 
  verifyTurnstile, 
  createTurnstileMiddleware, 
  TurnstileService 
} from './core-plugins/turnstile-plugin'
