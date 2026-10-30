/**
 * Plugin SDK
 *
 * Payload-shaped plugin authoring API for SonicJS v3+.
 *
 *   definePlugin({...})       — canonical plugin factory (identity + typed shape)
 *   registerPlugins(app, ...)  — single chokepoint for app-level registration
 *   ConfigSchema / Field      — schema-driven settings UI
 *
 * @packageDocumentation
 */

export { definePlugin, isDefinedPlugin } from './define-plugin'
export type {
  DefinePluginInput,
  DefinedPlugin,
  DefinedPluginContext,
  DeclarativeHooks,
} from './define-plugin'

export { registerPlugins, RegisterPluginsError } from './register-plugins'
export type {
  RegisterablePlugin,
  RegisterPluginsHostContext,
  RegisterPluginsErrorReason,
  PluginsRegistry,
  RegistryEntry,
} from './register-plugins'

export {
  parseConfigSchema,
  renderSchemaFields,
  parseFormDataToSettings,
  applySchemaDefaults,
} from './config-schema'
export type {
  ConfigSchema,
  ConfigSchemaField,
  StringField,
  NumberField,
  BooleanField,
  SelectField,
  ParsedField,
  SettingsFor,
} from './config-schema'
