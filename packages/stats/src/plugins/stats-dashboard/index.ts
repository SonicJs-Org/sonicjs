import { definePlugin } from '@sonicjs-cms/core'
import { statsDashboardAdminRoutes } from './routes/admin'

const DASHBOARD_ICON = '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 0 1 3 19.875v-6.75ZM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V8.625ZM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V4.125Z"/></svg>'

export const statsDashboardPlugin = definePlugin({
  id: 'stats-dashboard',
  version: '1.0.0',
  name: 'Stats Dashboard',
  description: 'Weekly installation funnel dashboard for stats.sonicjs.com.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  register(app) {
    // Inject Dashboard into sidebar menu for all admin pages.
    // pluginMenuMiddleware only reads from the compiled manifest registry,
    // so dynamically-registered plugins must self-inject via context.
    // This middleware runs inside pluginMenuMiddleware's next(), so the
    // context var is already initialised when we prepend our item.
    app.use('/admin/*', async (c, next) => {
      const existing = (c.get('pluginMenuItems') ?? []) as Array<{ label: string; path: string; icon: string }>
      if (!existing.some((m) => m.path === '/admin/dashboard')) {
        c.set('pluginMenuItems', [
          { label: 'Dashboard', path: '/admin/dashboard', icon: DASHBOARD_ICON },
          ...existing,
        ] as any)
      }
      return next()
    })
    app.route('/admin/dashboard', statsDashboardAdminRoutes as any)
  },

  menu: [
    {
      label: 'Dashboard',
      path: '/admin/dashboard',
      icon: 'chart-bar',
      order: 0,
      permissions: ['admin'],
    },
  ],
})
