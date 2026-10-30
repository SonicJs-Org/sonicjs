/**
 * Forms Plugin — Payload-shaped port.
 *
 * Form builder with Form.io integration, Turnstile CAPTCHA support, and
 * submission management via the content collection system.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { adminFormsRoutes } from '../../../routes/admin-forms'
import { publicFormsRoutes } from '../../../routes/public-forms'

export const formsPlugin = definePlugin({
  id: 'forms',
  version: '1.0.0',
  name: 'Forms',
  description: 'Form builder with Form.io integration, CAPTCHA support, and submission management.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  register(app) {
    app.route('/admin/forms', adminFormsRoutes as any)
    app.route('/forms', publicFormsRoutes as any)
    app.route('/api/forms', publicFormsRoutes as any)
  },

  menu: [
    { label: 'Forms', path: '/admin/forms', icon: 'document', order: 30, permissions: ['forms:manage'] },
  ],

  activate: async () => console.info('✅ Forms plugin activated'),
  deactivate: async () => console.info('❌ Forms plugin deactivated'),
})

export function createFormsPlugin() {
  return formsPlugin
}
