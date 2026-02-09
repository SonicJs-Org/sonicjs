import { PluginBuilder } from '../../sdk/plugin-builder'
import { Plugin } from '@sonicjs-cms/core'
import { createSeedDataAdminRoutes } from './admin-routes'
import { SeedDataService } from './services/seed-data-service'

export function createSeedDataPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: 'seed-data',
    version: '1.0.0-beta.1',
    description: 'Generate realistic users, content, forms, and submissions for testing and development'
  })

  builder.metadata({
    author: { name: 'SonicJS', email: 'admin@sonicjs.com' },
    license: 'MIT',
    compatibility: '^1.0.0',
    dependencies: []
  })

  // Add admin routes
  builder.addRoute('/admin/seed-data', createSeedDataAdminRoutes() as any, {
    description: 'Seed data tool routes',
    requiresAuth: true
  })

  // Add admin page
  builder.addAdminPage('/seed-data', 'Seed Data', 'SeedData', {
    description: 'Generate example users and content',
    icon: 'seedling',
    permissions: ['admin']
  })

  // Add menu item to admin sidebar
  builder.addMenuItem('Seed Data', '/admin/seed-data', {
    icon: 'seedling',
    order: 65,
    permissions: ['admin']
  })

  // Add service
  builder.addService('seedData', {
    implementation: SeedDataService,
    description: 'Seed data generation service',
    singleton: true
  })

  return builder.build() as Plugin
}

export const seedDataPlugin = createSeedDataPlugin()
export { SeedDataService } from './services/seed-data-service'
