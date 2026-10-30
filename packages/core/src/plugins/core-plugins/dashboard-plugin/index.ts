/**
 * Dashboard Plugin — Payload-shaped port.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { adminDashboardRoutes } from '../../../routes/admin-dashboard'

export const dashboardPlugin = definePlugin({
  id: 'dashboard',
  version: '1.0.0',
  name: 'Dashboard',
  description: 'Admin dashboard with stats, storage usage, and recent activity.',
  sonicjsVersionRange: '^3.0.0',

  register(app) {
    app.route('/admin/dashboard', adminDashboardRoutes as any)
  },

  menu: [
    { label: 'Dashboard', path: '/admin/dashboard', icon: 'chart', order: 1 },
  ],
})

export function createDashboardPlugin() {
  return dashboardPlugin
}
