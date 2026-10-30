import { definePlugin } from '@sonicjs-cms/core'
import { playwrightAdminRoutes } from './routes/admin'

const PLAYWRIGHT_ICON = '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'

export const playwrightDashboardPlugin = definePlugin({
  id: 'playwright-dashboard',
  version: '1.0.0',
  name: 'Playwright Dashboard',
  description: 'CI/CD Playwright run history, flaky test detection, and failure trends.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  register(app) {
    // Inject Playwright into sidebar menu for all admin pages.
    app.use('/admin/*', async (c, next) => {
      const existing = ((c as any).get('pluginMenuItems') ?? []) as Array<{ label: string; path: string; icon: string }>
      if (!existing.some((m) => m.path === '/admin/playwright')) {
        (c as any).set('pluginMenuItems', [
          ...existing,
          { label: 'Playwright', path: '/admin/playwright', icon: PLAYWRIGHT_ICON },
        ] as any)
      }
      return next()
    })
    app.route('/admin/playwright', playwrightAdminRoutes as any)
  },

  menu: [
    {
      label: 'Playwright',
      path: '/admin/playwright',
      icon: 'check-circle',
      order: 1,
      permissions: ['admin'],
    },
  ],
})
