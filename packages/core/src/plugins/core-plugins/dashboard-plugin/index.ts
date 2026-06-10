import { PluginBuilder } from '../../sdk/plugin-builder'
import type { Plugin } from '@sonicjs-cms/core'
import { adminDashboardRoutes } from '../../../routes/admin-dashboard'

export function createDashboardPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: 'dashboard',
    version: '1.0.0',
    description: 'Admin dashboard with stats, storage usage, and recent activity'
  })

  builder.addRoute('/admin/dashboard', adminDashboardRoutes as any, {
    description: 'Admin dashboard',
    requiresAuth: true,
    priority: 100
  })

  builder.addMenuItem('Dashboard', '/admin/dashboard', {
    icon: 'home',
    order: 1
  })

  return builder.build() as Plugin
}

export const dashboardPlugin = createDashboardPlugin()
