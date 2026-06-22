import { definePlugin } from '@sonicjs-cms/core'
import { statsDashboardAdminRoutes } from './routes/admin'

export const statsDashboardPlugin = definePlugin({
  id: 'stats-dashboard',
  version: '1.0.0',
  name: 'Stats Dashboard',
  description: 'Weekly installation funnel dashboard for stats.sonicjs.com.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  register(app) {
    app.route('/admin/dashboard', statsDashboardAdminRoutes as any)
  },

  menu: [
    {
      label: 'Dashboard',
      path: '/admin/dashboard',
      icon: 'chart',
      order: 0,
      permissions: ['admin'],
    },
  ],
})
