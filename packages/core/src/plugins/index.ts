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
} from './hooks/catalog'
export type {
  HookEventName,
  HookEventPayloads,
  HookPayload,
  ContentEventPayload,
  AuthRegistrationCompletedPayload,
  AuthPasswordResetRequestedPayload,
  AuthPasswordResetCompletedPayload,
} from './hooks/catalog'
export { createTypedHooks } from './hooks/typed-hooks'
export type { TypedHooks, TypedHookHandler, TypedHookContext, HookSystemLike } from './hooks/typed-hooks'
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
  createCapabilityContext,
} from './capabilities'
export type {
  Capability,
  FixedCapability,
  DbCapability,
  CapabilityProviders,
  PluginCapabilityContext,
} from './capabilities'

// Service singletons
export { createServiceSingleton } from './singletons/service-singleton'
export type { ServiceSingleton } from './singletons/service-singleton'

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
