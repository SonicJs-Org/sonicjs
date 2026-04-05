/**
 * SonicJS Plugin System Types
 * 
 * Defines the core interfaces and types for the plugin system
 */

import { Hono, Context, MiddlewareHandler } from 'hono'
import { z } from 'zod'
import type { D1Database, KVNamespace, R2Bucket } from '@cloudflare/workers-types'

// Core plugin definition
export interface Plugin {
  /** Unique plugin identifier */
  name: string
  /** Plugin version (semantic versioning) */
  version: string
  /** Human-readable description */
  description?: string
  /** Plugin author information */
  author?: {
    name: string
    email?: string
    url?: string
  }
  /** Plugin dependencies (other plugins required) */
  dependencies?: string[]
  /** SonicJS version compatibility */
  compatibility?: string
  /** Plugin license */
  license?: string
  
  // Extension points
  routes?: PluginRoutes[]
  middleware?: PluginMiddleware[]
  models?: PluginModel[]
  services?: PluginService[]
  adminPages?: PluginAdminPage[]
  adminComponents?: PluginComponent[]
  menuItems?: PluginMenuItem[]
  hooks?: PluginHook[]
  
  // Lifecycle hooks
  install?: (context: PluginContext) => Promise<void>
  uninstall?: (context: PluginContext) => Promise<void>
  activate?: (context: PluginContext) => Promise<void>
  deactivate?: (context: PluginContext) => Promise<void>
  configure?: (config: PluginConfig) => Promise<void>
}

// Plugin context provides access to SonicJS APIs
export interface PluginContext {
  /** Database instance */
  db: D1Database
  /** Key-value storage */
  kv: KVNamespace
  /** R2 storage bucket */
  r2?: R2Bucket
  /** Plugin configuration */
  config: PluginConfig
  /** Core SonicJS services */
  services: {
    auth: AuthService
    content: ContentService
    media: MediaService
  }
  /** Hook system for inter-plugin communication */
  hooks: HookSystem | ScopedHookSystem
  /** Logging utilities */
  logger: PluginLogger
}

// Plugin configuration
export interface PluginConfig {
  /** Plugin-specific configuration */
  [key: string]: any
  /** Whether plugin is enabled */
  enabled: boolean
  /** Plugin installation timestamp */
  installedAt?: number
  /** Plugin last update timestamp */
  updatedAt?: number
}

// Route definitions
export interface PluginRoutes {
  /** Route path prefix */
  path: string
  /** Hono route handler */
  handler: Hono
  /** Route description */
  description?: string
  /** Whether route requires authentication */
  requiresAuth?: boolean
  /** Required roles for access */
  roles?: string[]
  /** Route priority (for ordering) */
  priority?: number
}

// Middleware definitions
export interface PluginMiddleware {
  /** Middleware name */
  name: string
  /** Middleware handler function */
  handler: MiddlewareHandler
  /** Middleware description */
  description?: string
  /** Middleware priority (lower = earlier) */
  priority?: number
  /** Routes to apply middleware to */
  routes?: string[]
  /** Whether to apply globally */
  global?: boolean
}

// Database model definitions
export interface PluginModel {
  /** Model name */
  name: string
  /** Database table name */
  tableName: string
  /** Zod schema for validation */
  schema: z.ZodSchema
  /** Database migrations */
  migrations: string[]
  /** Model relationships */
  relationships?: ModelRelationship[]
  /** Whether model extends core content */
  extendsContent?: boolean
}

export interface ModelRelationship {
  type: 'oneToOne' | 'oneToMany' | 'manyToMany'
  target: string
  foreignKey?: string
  joinTable?: string
}

// Service definitions
export interface PluginService {
  /** Service name */
  name: string
  /** Service implementation */
  implementation: any
  /** Service description */
  description?: string
  /** Service dependencies */
  dependencies?: string[]
  /** Whether service is singleton */
  singleton?: boolean
}

// Admin interface extensions
export interface PluginAdminPage {
  /** Page path (relative to /admin) */
  path: string
  /** Page title */
  title: string
  /** Page component/template */
  component: string
  /** Page description */
  description?: string
  /** Required permissions */
  permissions?: string[]
  /** Menu item configuration */
  menuItem?: PluginMenuItem
  /** Page icon */
  icon?: string
}

export interface PluginComponent {
  /** Component name */
  name: string
  /** Component template function */
  template: (props: any) => string
  /** Component description */
  description?: string
  /** Component props schema */
  propsSchema?: z.ZodSchema
}

export interface PluginMenuItem {
  /** Menu item label */
  label: string
  /** Menu item path */
  path: string
  /** Menu item icon */
  icon?: string
  /** Menu item order */
  order?: number
  /** Parent menu item */
  parent?: string
  /** Required permissions */
  permissions?: string[]
  /** Whether item is active */
  active?: boolean
}

// Hook system for extensibility
export interface PluginHook {
  /** Hook name */
  name: string
  /** Hook handler function */
  handler: HookHandler
  /** Hook priority */
  priority?: number
  /** Hook description */
  description?: string
}

export type HookHandler = (data: any, context: HookContext) => Promise<any>

export interface HookContext {
  /** Plugin that registered the hook */
  plugin: string
  /** Hook execution context */
  context: PluginContext
  /** Cancel hook execution */
  cancel?: () => void
}

// Hook system interface
export interface HookSystem {
  /** Register a hook handler */
  register(hookName: string, handler: HookHandler, priority?: number): void
  /** Execute all handlers for a hook */
  execute(hookName: string, data: any, context?: any): Promise<any>
  /** Remove a hook handler */
  unregister(hookName: string, handler: HookHandler): void
  /** Get all registered hooks */
  getHooks(hookName: string): PluginHook[]
  /** Create a scoped hook system (optional) */
  createScope?(pluginName: string): ScopedHookSystem
}

// Scoped hook system for plugins
export interface ScopedHookSystem {
  /** Register a hook handler */
  register(hookName: string, handler: HookHandler, priority?: number): void
  /** Execute all handlers for a hook */
  execute(hookName: string, data: any, context?: any): Promise<any>
  /** Remove a hook handler */
  unregister(hookName: string, handler: HookHandler): void
  /** Remove all hooks for this scope */
  unregisterAll(): void
}

// Plugin registry
export interface PluginRegistry {
  /** Get plugin by name */
  get(name: string): Plugin | undefined
  /** Get all registered plugins */
  getAll(): Plugin[]
  /** Get active plugins */
  getActive(): Plugin[]
  /** Register a plugin */
  register(plugin: Plugin): Promise<void>
  /** Unregister a plugin */
  unregister(name: string): Promise<void>
  /** Check if plugin is registered */
  has(name: string): boolean
  /** Activate a plugin */
  activate(name: string): Promise<void>
  /** Deactivate a plugin */
  deactivate(name: string): Promise<void>
  /** Get plugin configuration */
  getConfig(name: string): PluginConfig | undefined
  /** Set plugin configuration */
  setConfig(name: string, config: PluginConfig): void
  /** Get plugin status */
  getStatus(name: string): PluginStatus | undefined
  /** Get all plugin statuses */
  getAllStatuses(): Map<string, PluginStatus>
  /** Resolve plugin load order based on dependencies */
  resolveLoadOrder(): string[]
}

// Plugin manager
export interface PluginManager {
  /** Plugin registry */
  registry: PluginRegistry
  /** Hook system */
  hooks: HookSystem
  /** Initialize plugin system */
  initialize(context: PluginContext): Promise<void>
  /** Load plugins from configuration */
  loadPlugins(config: PluginConfig[]): Promise<void>
  /** Install a plugin */
  install(plugin: Plugin, config?: PluginConfig): Promise<void>
  /** Uninstall a plugin */
  uninstall(name: string): Promise<void>
  /** Get plugin status */
  getStatus(name: string): PluginStatus
}

export interface PluginStatus {
  name: string
  version: string
  active: boolean
  installed: boolean
  hasErrors: boolean
  errors?: string[]
  lastError?: string
}

// Service interfaces
export interface AuthService {
  /** Verify user permissions */
  hasPermission(userId: string, permission: string): Promise<boolean>
  /** Get current user */
  getCurrentUser(context: Context): Promise<any>
  /** Create authentication middleware */
  createMiddleware(options?: any): MiddlewareHandler
}

export interface ContentService {
  /** Get content by ID */
  getById(id: string): Promise<any>
  /** Create new content */
  create(data: any): Promise<any>
  /** Update content */
  update(id: string, data: any): Promise<any>
  /** Delete content */
  delete(id: string): Promise<void>
  /** Search content */
  search(query: string, options?: any): Promise<any[]>
}

export interface MediaService {
  /** Upload file */
  upload(file: File, options?: any): Promise<any>
  /** Get media by ID */
  getById(id: string): Promise<any>
  /** Delete media */
  delete(id: string): Promise<void>
  /** Transform image */
  transform(id: string, options: any): Promise<string>
}

// Plugin logger
export interface PluginLogger {
  debug(message: string, data?: any): void
  info(message: string, data?: any): void
  warn(message: string, data?: any): void
  error(message: string, error?: Error, data?: any): void
}

// Plugin development utilities interface

export interface PluginBuilderOptions {
  name: string
  version: string
  description?: string
  author?: Plugin['author']
  dependencies?: string[]
}

// Plugin validation
export interface PluginValidator {
  /** Validate plugin definition */
  validate(plugin: Plugin): PluginValidationResult
  /** Validate plugin dependencies */
  validateDependencies(plugin: Plugin, registry: PluginRegistry): PluginValidationResult
  /** Validate plugin compatibility */
  validateCompatibility(plugin: Plugin, version: string): PluginValidationResult
}

export interface PluginValidationResult {
  valid: boolean
  errors: string[]
  warnings: string[]
}

// Standard hook names
export const HOOKS = {
  // Application lifecycle
  APP_INIT: 'app:init',
  APP_READY: 'app:ready',
  APP_SHUTDOWN: 'app:shutdown',
  
  // Request lifecycle
  REQUEST_START: 'request:start',
  REQUEST_END: 'request:end',
  REQUEST_ERROR: 'request:error',
  
  // Authentication
  AUTH_LOGIN: 'auth:login',
  AUTH_LOGOUT: 'auth:logout',
  AUTH_REGISTER: 'auth:register',
  USER_LOGIN: 'user:login',
  USER_LOGOUT: 'user:logout',
  
  // Content lifecycle
  CONTENT_CREATE: 'content:create',
  CONTENT_READ: 'content:read',
  CONTENT_UPDATE: 'content:update',
  CONTENT_DELETE: 'content:delete',
  CONTENT_PUBLISH: 'content:publish',
  CONTENT_SAVE: 'content:save',
  
  // Media lifecycle
  MEDIA_UPLOAD: 'media:upload',
  MEDIA_DELETE: 'media:delete',
  MEDIA_TRANSFORM: 'media:transform',
  
  // Plugin lifecycle
  PLUGIN_INSTALL: 'plugin:install',
  PLUGIN_UNINSTALL: 'plugin:uninstall',
  PLUGIN_ACTIVATE: 'plugin:activate',
  PLUGIN_DEACTIVATE: 'plugin:deactivate',
  
  // Admin interface
  ADMIN_MENU_RENDER: 'admin:menu:render',
  ADMIN_PAGE_RENDER: 'admin:page:render',
  
  // Database
  DB_MIGRATE: 'db:migrate',
  DB_SEED: 'db:seed',
} as const

export type HookName = typeof HOOKS[keyof typeof HOOKS]