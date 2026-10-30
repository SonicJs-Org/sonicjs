/**
 * Plugin Validator
 * 
 * Validates plugin definitions, dependencies, and compatibility
 */

import { z } from 'zod'
import { Plugin, PluginValidator as IPluginValidator, PluginValidationResult, PluginRegistry } from '../types'
import semver from 'semver'

// Zod schemas for plugin validation
const PluginAuthorSchema = z.object({
  name: z.string().min(1),
  email: z.string().email().optional(),
  url: z.string().url().optional(),
})

const PluginRoutesSchema = z.object({
  path: z.string().min(1),
  handler: z.any(), // Hono instance
  description: z.string().optional(),
  requiresAuth: z.boolean().optional(),
  roles: z.array(z.string()).optional(),
  priority: z.number().optional(),
})

const PluginMiddlewareSchema = z.object({
  name: z.string().min(1),
  handler: z.function(),
  description: z.string().optional(),
  priority: z.number().optional(),
  routes: z.array(z.string()).optional(),
  global: z.boolean().optional(),
})

const PluginModelSchema = z.object({
  name: z.string().min(1),
  tableName: z.string().min(1),
  schema: z.any(), // Zod schema
  migrations: z.array(z.string()),
  relationships: z.array(z.object({
    type: z.enum(['oneToOne', 'oneToMany', 'manyToMany']),
    target: z.string(),
    foreignKey: z.string().optional(),
    joinTable: z.string().optional(),
  })).optional(),
  extendsContent: z.boolean().optional(),
})

const PluginServiceSchema = z.object({
  name: z.string().min(1),
  implementation: z.any(),
  description: z.string().optional(),
  dependencies: z.array(z.string()).optional(),
  singleton: z.boolean().optional(),
})

const PluginAdminPageSchema = z.object({
  path: z.string().min(1),
  title: z.string().min(1),
  component: z.string().min(1),
  description: z.string().optional(),
  permissions: z.array(z.string()).optional(),
  menuItem: z.object({
    label: z.string(),
    path: z.string(),
    icon: z.string().optional(),
    order: z.number().optional(),
    parent: z.string().optional(),
    permissions: z.array(z.string()).optional(),
    active: z.boolean().optional(),
  }).optional(),
  icon: z.string().optional(),
})

const PluginComponentSchema = z.object({
  name: z.string().min(1),
  template: z.function(),
  description: z.string().optional(),
  propsSchema: z.any().optional(), // Zod schema
})

const PluginHookSchema = z.object({
  name: z.string().min(1),
  handler: z.function(),
  priority: z.number().optional(),
  description: z.string().optional(),
})

const PluginSchema = z.object({
  name: z.string().min(1).regex(/^[a-z0-9-]+$/, 'Plugin name must be lowercase with hyphens'),
  version: z.string().refine(v => semver.valid(v), 'Version must be valid semver'),
  description: z.string().optional(),
  author: PluginAuthorSchema.optional(),
  dependencies: z.array(z.string()).optional(),
  compatibility: z.string().optional(),
  license: z.string().optional(),
  
  // Extension points
  routes: z.array(PluginRoutesSchema).optional(),
  middleware: z.array(PluginMiddlewareSchema).optional(),
  models: z.array(PluginModelSchema).optional(),
  services: z.array(PluginServiceSchema).optional(),
  adminPages: z.array(PluginAdminPageSchema).optional(),
  adminComponents: z.array(PluginComponentSchema).optional(),
  menuItems: z.array(z.object({
    label: z.string(),
    path: z.string(),
    icon: z.string().optional(),
    order: z.number().optional(),
    parent: z.string().optional(),
    permissions: z.array(z.string()).optional(),
    active: z.boolean().optional(),
  })).optional(),
  hooks: z.array(PluginHookSchema).optional(),
  
  // Lifecycle hooks
  install: z.function().optional(),
  uninstall: z.function().optional(),
  activate: z.function().optional(),
  deactivate: z.function().optional(),
  configure: z.function().optional(),
})

export class PluginValidator implements IPluginValidator {
  private static readonly RESERVED_NAMES = [
    'core', 'system', 'admin', 'api', 'auth', 'content', 'media', 'auth_user', 'collections'
  ]

  private static readonly RESERVED_PATHS = [
    '/admin', '/api', '/auth', '/docs', '/media', '/_assets'
  ]

  /**
   * Validate plugin definition
   */
  validate(plugin: Plugin): PluginValidationResult {
    const errors: string[] = []
    const warnings: string[] = []

    try {
      // Schema validation
      const result = PluginSchema.safeParse(plugin)
      if (!result.success) {
        result.error.issues.forEach((err: any) => {
          errors.push(`${err.path.join('.')}: ${err.message}`)
        })
      }

      // Reserved name validation
      if (PluginValidator.RESERVED_NAMES.includes(plugin.name)) {
        errors.push(`Plugin name "${plugin.name}" is reserved`)
      }

      // Route path validation
      if (plugin.routes) {
        for (const route of plugin.routes) {
          if (PluginValidator.RESERVED_PATHS.some(path => route.path.startsWith(path))) {
            errors.push(`Route path "${route.path}" conflicts with reserved system path`)
          }
          
          if (!route.path.startsWith('/')) {
            errors.push(`Route path "${route.path}" must start with /`)
          }
        }
      }

      // Model validation
      if (plugin.models) {
        const modelNames = new Set<string>()
        const tableNames = new Set<string>()
        
        for (const model of plugin.models) {
          // Check for duplicate model names
          if (modelNames.has(model.name)) {
            errors.push(`Duplicate model name: ${model.name}`)
          }
          modelNames.add(model.name)
          
          // Check for duplicate table names
          if (tableNames.has(model.tableName)) {
            errors.push(`Duplicate table name: ${model.tableName}`)
          }
          tableNames.add(model.tableName)
          
          // Validate table name format
          if (!/^[a-z][a-z0-9_]*$/.test(model.tableName)) {
            errors.push(`Invalid table name format: ${model.tableName}`)
          }
          
          // Check for system table conflicts
          const systemTables = ['auth_user', 'collections', 'content', 'content_versions', 'media', 'auth_api_tokens']
          if (systemTables.includes(model.tableName)) {
            errors.push(`Table name "${model.tableName}" conflicts with system table`)
          }
        }
      }

      // Service validation
      if (plugin.services) {
        const serviceNames = new Set<string>()
        
        for (const service of plugin.services) {
          if (serviceNames.has(service.name)) {
            errors.push(`Duplicate service name: ${service.name}`)
          }
          serviceNames.add(service.name)
          
          // Check for system service conflicts
          const systemServices = ['auth', 'content', 'media', 'cdn']
          if (systemServices.includes(service.name)) {
            warnings.push(`Service name "${service.name}" conflicts with system service`)
          }
        }
      }

      // Admin page validation
      if (plugin.adminPages) {
        const pagePaths = new Set<string>()
        
        for (const page of plugin.adminPages) {
          if (pagePaths.has(page.path)) {
            errors.push(`Duplicate admin page path: ${page.path}`)
          }
          pagePaths.add(page.path)
          
          if (!page.path.startsWith('/')) {
            errors.push(`Admin page path "${page.path}" must start with /`)
          }
          
          // Check for system admin page conflicts
          const systemPaths = ['/', '/collections', '/content', '/media', '/users', '/settings']
          if (systemPaths.includes(page.path)) {
            errors.push(`Admin page path "${page.path}" conflicts with system page`)
          }
        }
      }

      // Component validation
      if (plugin.adminComponents) {
        const componentNames = new Set<string>()
        
        for (const component of plugin.adminComponents) {
          if (componentNames.has(component.name)) {
            errors.push(`Duplicate component name: ${component.name}`)
          }
          componentNames.add(component.name)
          
          // Check for system component conflicts
          const systemComponents = ['table', 'form', 'alert', 'media-grid', 'pagination']
          if (systemComponents.includes(component.name)) {
            warnings.push(`Component name "${component.name}" conflicts with system component`)
          }
        }
      }

      // Hook validation
      if (plugin.hooks) {
        for (const hook of plugin.hooks) {
          if (!hook.name.includes(':')) {
            warnings.push(`Hook name "${hook.name}" should include namespace (e.g., "plugin:event")`)
          }
        }
      }

      // Dependency cycle detection (basic)
      if (plugin.dependencies?.includes(plugin.name)) {
        errors.push(`Plugin cannot depend on itself`)
      }

      // License validation
      if (plugin.license) {
        const validLicenses = ['MIT', 'Apache-2.0', 'GPL-3.0', 'BSD-3-Clause', 'ISC']
        if (!validLicenses.includes(plugin.license)) {
          warnings.push(`License "${plugin.license}" is not a common SPDX identifier`)
        }
      }

      // Performance warnings
      if (plugin.middleware && plugin.middleware.length > 5) {
        warnings.push(`Plugin defines ${plugin.middleware.length} middleware functions, consider consolidating`)
      }

      if (plugin.hooks && plugin.hooks.length > 10) {
        warnings.push(`Plugin defines ${plugin.hooks.length} hooks, ensure they are necessary`)
      }

    } catch (error) {
      errors.push(`Validation error: ${error instanceof Error ? error.message : String(error)}`)
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    }
  }

  /**
   * Validate plugin dependencies
   */
  validateDependencies(plugin: Plugin, registry: PluginRegistry): PluginValidationResult {
    const errors: string[] = []
    const warnings: string[] = []

    if (!plugin.dependencies || plugin.dependencies.length === 0) {
      return { valid: true, errors, warnings }
    }

    // Check if all dependencies are registered
    for (const depName of plugin.dependencies) {
      if (!registry.has(depName)) {
        errors.push(`Dependency "${depName}" is not registered`)
        continue
      }

      const dependency = registry.get(depName)!
      
      // Check dependency version compatibility
      if (dependency.compatibility && plugin.compatibility) {
        if (!this.isCompatible(dependency.compatibility, plugin.compatibility)) {
          warnings.push(`Potential compatibility issue with dependency "${depName}"`)
        }
      }
    }

    // Check for circular dependencies
    const visited = new Set<string>()
    const visiting = new Set<string>()
    
    const checkCircular = (name: string): boolean => {
      if (visiting.has(name)) return true
      if (visited.has(name)) return false
      
      visiting.add(name)
      
      const current = registry.get(name)
      if (current?.dependencies) {
        for (const depName of current.dependencies) {
          if (checkCircular(depName)) {
            errors.push(`Circular dependency detected: ${name} -> ${depName}`)
            return true
          }
        }
      }
      
      visiting.delete(name)
      visited.add(name)
      return false
    }

    checkCircular(plugin.name)

    return {
      valid: errors.length === 0,
      errors,
      warnings
    }
  }

  /**
   * Validate plugin compatibility with SonicJS version
   */
  validateCompatibility(plugin: Plugin, sonicVersion: string): PluginValidationResult {
    const errors: string[] = []
    const warnings: string[] = []

    if (!plugin.compatibility) {
      warnings.push('Plugin does not specify compatibility version')
      return { valid: true, errors, warnings }
    }

    try {
      if (!semver.satisfies(sonicVersion, plugin.compatibility)) {
        errors.push(`Plugin requires SonicJS ${plugin.compatibility}, but current version is ${sonicVersion}`)
      }
    } catch (error) {
      errors.push(`Invalid compatibility version format: ${plugin.compatibility}`)
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    }
  }

  /**
   * Check if two version ranges are compatible
   */
  private isCompatible(version1: string, version2: string): boolean {
    try {
      // Simple compatibility check - can be enhanced
      return semver.intersects(version1, version2)
    } catch {
      return false
    }
  }

  /**
   * Validate plugin security constraints
   */
  validateSecurity(plugin: Plugin): PluginValidationResult {
    const errors: string[] = []
    const warnings: string[] = []

    // Check for potentially dangerous patterns
    const pluginCode = JSON.stringify(plugin)
    
    // Check for eval or Function constructor usage
    if (pluginCode.includes('eval(') || pluginCode.includes('Function(')) {
      errors.push('Plugin contains potentially dangerous code execution patterns')
    }

    // Check for file system access attempts
    if (pluginCode.includes('fs.') || pluginCode.includes('require(')) {
      warnings.push('Plugin may attempt file system access (not available in Cloudflare Workers)')
    }

    // Check for network access patterns
    if (pluginCode.includes('fetch(') || pluginCode.includes('XMLHttpRequest')) {
      warnings.push('Plugin contains network access code - ensure it follows security guidelines')
    }

    // Check for sensitive data patterns
    const sensitivePatterns = ['password', 'secret', 'key', 'token', 'credential']
    for (const pattern of sensitivePatterns) {
      if (pluginCode.toLowerCase().includes(pattern)) {
        warnings.push(`Plugin code contains "${pattern}" - ensure sensitive data is properly handled`)
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    }
  }
}