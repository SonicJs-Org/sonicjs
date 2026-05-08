/**
 * Plugin Manager
 * 
 * Central orchestrator for the plugin system
 */

import { Hono } from 'hono'
import { Plugin, PluginManager as IPluginManager, PluginRegistry, PluginConfig, PluginContext, PluginStatus, HookSystem, PluginLogger, HOOKS, PluginRoutes } from '../types'
import { PluginRegistryImpl } from './plugin-registry'
import { HookSystemImpl, ScopedHookSystem } from './hook-system'
import { PluginValidator } from './plugin-validator'

export class PluginManager implements IPluginManager {
  public readonly registry: PluginRegistry
  public readonly hooks: HookSystem
  private validator: PluginValidator
  private context?: PluginContext
  private scopedHooks: Map<string, ScopedHookSystem> = new Map()
  private pluginRoutes: Map<string, Hono> = new Map()

  constructor() {
    this.validator = new PluginValidator()
    this.registry = new PluginRegistryImpl(this.validator)
    this.hooks = new HookSystemImpl()
  }

  /**
   * Initialize plugin system
   */
  async initialize(context: PluginContext): Promise<void> {
    console.info('Initializing plugin system...')
    
    this.context = context
    
    // Execute app init hook
    await this.hooks.execute(HOOKS.APP_INIT, {
      pluginManager: this,
      context
    })

    console.info('Plugin system initialized')
  }

  /**
   * Load plugins from configuration
   */
  async loadPlugins(configs: PluginConfig[]): Promise<void> {
    console.info(`Loading ${configs.length} plugins...`)

    // Filter enabled plugins
    const enabledConfigs = configs.filter(config => config.enabled)
    
    if (enabledConfigs.length === 0) {
      console.info('No enabled plugins to load')
      return
    }

    // Load and register plugins (implementation would depend on how plugins are distributed)
    for (const config of enabledConfigs) {
      try {
        // In a real implementation, this would load the plugin from a registry or file system
        // For now, we'll assume plugins are already imported
        console.info(`Loading plugin configuration: ${JSON.stringify(config)}`)
        
        // Store configuration
        if ('name' in config) {
          this.registry.setConfig(config.name as string, config)
        }
      } catch (error) {
        console.error(`Failed to load plugin configuration:`, error)
      }
    }

    // Resolve load order based on dependencies
    try {
      const loadOrder = this.registry.resolveLoadOrder()
      console.info(`Plugin load order: ${loadOrder.join(' -> ')}`)

      // Activate plugins in dependency order
      for (const pluginName of loadOrder) {
        const config = this.registry.getConfig(pluginName)
        if (config?.enabled) {
          await this.registry.activate(pluginName)
        }
      }
    } catch (error) {
      console.error('Failed to resolve plugin load order:', error)
    }

    console.info('Plugin loading completed')
  }

  /**
   * Install a plugin
   */
  async install(plugin: Plugin, config?: PluginConfig): Promise<void> {
    console.info(`Installing plugin: ${plugin.name}`)

    if (!this.context) {
      throw new Error('Plugin manager not initialized')
    }

    try {
      // Validate plugin
      const validation = this.validator.validate(plugin)
      if (!validation.valid) {
        throw new Error(`Plugin validation failed: ${validation.errors.join(', ')}`)
      }

      // Register plugin
      await this.registry.register(plugin)

      // Set configuration
      const pluginConfig: PluginConfig = {
        enabled: true,
        installedAt: Date.now(),
        ...config
      }
      this.registry.setConfig(plugin.name, pluginConfig)

      // Create scoped hook system for plugin
      const scopedHooks = this.hooks.createScope ? 
        (this.hooks as HookSystemImpl).createScope(plugin.name) : 
        this.hooks

      this.scopedHooks.set(plugin.name, scopedHooks as ScopedHookSystem)

      // Create plugin context
      const pluginContext: PluginContext = {
        ...this.context,
        config: pluginConfig,
        hooks: scopedHooks,
        logger: this.createLogger(plugin.name)
      }

      // Register plugin extensions
      await this.registerPluginExtensions(plugin, pluginContext)

      // Run plugin install hook
      if (plugin.install) {
        await plugin.install(pluginContext)
      }

      // Execute plugin install hook
      await this.hooks.execute(HOOKS.PLUGIN_INSTALL, {
        plugin: plugin.name,
        version: plugin.version,
        context: pluginContext
      })

      console.info(`Plugin installed successfully: ${plugin.name}`)
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      console.error(`Failed to install plugin ${plugin.name}:`, errorMessage)
      
      // Update status with error
      const status = this.registry.getStatus(plugin.name)
      if (status) {
        this.updatePluginStatus(plugin.name, {
          hasErrors: true,
          errors: [...(status.errors || []), errorMessage],
          lastError: errorMessage
        })
      }
      
      throw error
    }
  }

  /**
   * Uninstall a plugin
   */
  async uninstall(name: string): Promise<void> {
    console.info(`Uninstalling plugin: ${name}`)

    const plugin = this.registry.get(name)
    if (!plugin) {
      throw new Error(`Plugin not found: ${name}`)
    }

    if (!this.context) {
      throw new Error('Plugin manager not initialized')
    }

    try {
      // Deactivate plugin first
      const status = this.registry.getStatus(name)
      if (status?.active) {
        await this.registry.deactivate(name)
      }

      // Create plugin context
      const config = this.registry.getConfig(name) || { enabled: false }
      const pluginContext: PluginContext = {
        ...this.context,
        config,
        hooks: this.scopedHooks.get(name) || this.hooks,
        logger: this.createLogger(name)
      }

      // Run plugin uninstall hook
      if (plugin.uninstall) {
        await plugin.uninstall(pluginContext)
      }

      // Unregister plugin extensions
      await this.unregisterPluginExtensions(plugin)

      // Clean up scoped hooks
      const scopedHooks = this.scopedHooks.get(name)
      if (scopedHooks && 'unregisterAll' in scopedHooks) {
        scopedHooks.unregisterAll()
      }
      this.scopedHooks.delete(name)

      // Remove plugin routes
      this.pluginRoutes.delete(name)

      // Execute plugin uninstall hook
      await this.hooks.execute(HOOKS.PLUGIN_UNINSTALL, {
        plugin: name,
        context: pluginContext
      })

      // Unregister plugin
      await this.registry.unregister(name)

      console.info(`Plugin uninstalled successfully: ${name}`)
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      console.error(`Failed to uninstall plugin ${name}:`, errorMessage)
      throw error
    }
  }

  /**
   * Get plugin status
   */
  getStatus(name: string): PluginStatus {
    const status = this.registry.getStatus(name)
    if (!status) {
      return {
        name,
        version: 'unknown',
        active: false,
        installed: false,
        hasErrors: false
      }
    }
    return status
  }

  /**
   * Get all plugin statuses
   */
  getAllStatuses(): PluginStatus[] {
    return Array.from(this.registry.getAllStatuses().values())
  }

  registerPluginRoutes(plugin: { name: string; routes?: PluginRoutes[] }): void {
    if (!plugin.routes) {
      return
    }

    const pluginApp = new Hono()

    for (const route of plugin.routes) {
      pluginApp.route(route.path, route.handler)
    }

    this.pluginRoutes.set(plugin.name, pluginApp)
  }

  /**
   * Register plugin extensions (routes, middleware, etc.)
   */
  private async registerPluginExtensions(plugin: Plugin, _context: PluginContext): Promise<void> {
    this.registerPluginRoutes(plugin)

    // Register middleware
    if (plugin.middleware) {
      for (const middleware of plugin.middleware) {
        console.debug(`Registering plugin middleware: ${middleware.name}`)
        // Middleware registration would be handled by the main app
      }
    }

    // Register hooks
    if (plugin.hooks) {
      const scopedHooks = this.scopedHooks.get(plugin.name)
      for (const hook of plugin.hooks) {
        console.debug(`Registering plugin hook: ${hook.name}`)
        if (scopedHooks) {
          scopedHooks.register(hook.name, hook.handler, hook.priority)
        } else {
          this.hooks.register(hook.name, hook.handler, hook.priority)
        }
      }
    }

    // Register services
    if (plugin.services) {
      for (const service of plugin.services) {
        console.debug(`Registering plugin service: ${service.name}`)
        // Service registration would be handled by a service container
      }
    }

    // Register database models
    if (plugin.models) {
      for (const model of plugin.models) {
        console.debug(`Registering plugin model: ${model.name}`)
        // Model registration would involve database migrations
      }
    }
  }

  /**
   * Unregister plugin extensions
   */
  private async unregisterPluginExtensions(plugin: Plugin): Promise<void> {
    // Clean up is mostly handled by the scoped systems
    console.debug(`Unregistering extensions for plugin: ${plugin.name}`)
  }

  /**
   * Update plugin status
   */
  private updatePluginStatus(name: string, updates: Partial<PluginStatus>): void {
    const current = this.registry.getStatus(name)
    if (current && 'updateStatus' in this.registry) {
      // This would require extending the registry interface
      console.debug(`Updating status for plugin: ${name}`, updates)
    }
  }

  /**
   * Create a logger for a plugin
   */
  private createLogger(pluginName: string): PluginLogger {
    return {
      debug: (message: string, data?: any) => {
        console.debug(`[Plugin:${pluginName}] ${message}`, data || '')
      },
      info: (message: string, data?: any) => {
        console.info(`[Plugin:${pluginName}] ${message}`, data || '')
      },
      warn: (message: string, data?: any) => {
        console.warn(`[Plugin:${pluginName}] ${message}`, data || '')
      },
      error: (message: string, error?: Error, data?: any) => {
        console.error(`[Plugin:${pluginName}] ${message}`, error || '', data || '')
      }
    }
  }

  /**
   * Get plugin routes for mounting in main app
   */
  getPluginRoutes(): Map<string, Hono> {
    return new Map(this.pluginRoutes)
  }

  /**
   * Get plugin middleware for main app
   */
  getPluginMiddleware(): Array<{ name: string; handler: any; priority: number; global: boolean }> {
    const middleware: Array<{ name: string; handler: any; priority: number; global: boolean }> = []
    
    for (const plugin of this.registry.getActive()) {
      if (plugin.middleware) {
        for (const mw of plugin.middleware) {
          middleware.push({
            name: `${plugin.name}:${mw.name}`,
            handler: mw.handler,
            priority: mw.priority || 10,
            global: mw.global || false
          })
        }
      }
    }
    
    // Sort by priority
    return middleware.sort((a, b) => a.priority - b.priority)
  }

  /**
   * Execute shutdown procedures
   */
  async shutdown(): Promise<void> {
    console.info('Shutting down plugin system...')
    
    // Execute app shutdown hook
    await this.hooks.execute(HOOKS.APP_SHUTDOWN, {
      pluginManager: this
    })

    // Deactivate all active plugins
    const activePlugins = this.registry.getActive()
    for (const plugin of activePlugins.reverse()) { // Reverse order
      try {
        await this.registry.deactivate(plugin.name)
      } catch (error) {
        console.error(`Error deactivating plugin ${plugin.name}:`, error)
      }
    }

    console.info('Plugin system shutdown completed')
  }

  /**
   * Get plugin system statistics
   */
  getStats(): {
    registry: ReturnType<PluginRegistryImpl['getStats']>
    hooks: Array<{ hookName: string; handlerCount: number }>
    routes: number
    middleware: number
  } {
    return {
      registry: (this.registry as PluginRegistryImpl).getStats(),
      hooks: (this.hooks as HookSystemImpl).getStats(),
      routes: this.pluginRoutes.size,
      middleware: this.getPluginMiddleware().length
    }
  }
}
