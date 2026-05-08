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

// Public core plugin exports
export {
  aiSearchPlugin,
  AISearchService,
  IndexManager,
} from './core-plugins/ai-search-plugin'
export {
  analyticsPlugin,
  createAnalyticsPlugin,
} from './core-plugins/analytics'
export {
  globalVariablesPlugin,
  createGlobalVariablesPlugin,
  resolveVariables,
  resolveVariablesInObject,
  getVariableBlotScript,
  getVariableTinyMceScript,
} from './core-plugins/global-variables-plugin'
export {
  oauthProvidersPlugin,
  createOAuthProvidersPlugin,
} from './core-plugins/oauth-providers'
export {
  OAuthService,
  BUILT_IN_PROVIDERS,
} from './core-plugins/oauth-providers/oauth-service'
export {
  securityAuditPlugin,
  createSecurityAuditPlugin,
  SecurityAuditService,
  BruteForceDetector,
  securityAuditMiddleware,
} from './core-plugins/security-audit-plugin'
export {
  shortcodesPlugin,
  createShortcodesPlugin,
  resolveShortcodes,
  resolveShortcodesInObject,
  registerShortcodeHandler,
  getShortcodeBlotScript,
  getShortcodeTinyMceScript,
} from './core-plugins/shortcodes-plugin'
export {
  stripePlugin,
  createStripePlugin,
  SubscriptionService,
  StripeAPI,
  requireSubscription,
} from './core-plugins/stripe-plugin'
export {
  verifyTurnstile,
  createTurnstileMiddleware,
  TurnstileService,
  turnstilePlugin,
} from './core-plugins/turnstile-plugin'
export {
  userProfilesPlugin,
  createUserProfilesPlugin,
  defineUserProfile,
  getUserProfileConfig,
} from './core-plugins/user-profiles'
export type { ProfileFieldDefinition, UserProfileConfig } from './core-plugins/user-profiles'
