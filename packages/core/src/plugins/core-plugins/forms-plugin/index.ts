/**
 * Forms Plugin
 *
 * Form builder with Form.io integration, Turnstile CAPTCHA support,
 * and submission management via the content collection system.
 */

import type { Plugin } from '../../types'
import { PluginBuilder } from '../../sdk/plugin-builder'
import { adminFormsRoutes } from '../../../routes/admin-forms'
import { publicFormsRoutes } from '../../../routes/public-forms'

export function createFormsPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: 'forms',
    version: '1.0.0',
    description: 'Form builder with Form.io integration, CAPTCHA support, and submission management'
  })

  builder.metadata({
    author: {
      name: 'SonicJS Team',
      email: 'team@sonicjs.com'
    },
    license: 'MIT',
    compatibility: '^2.0.0'
  })

  // Admin UI — form builder and submissions management
  builder.addRoute('/admin/forms', adminFormsRoutes as any, {
    description: 'Forms admin management',
    requiresAuth: true,
    priority: 30
  })

  // Public form rendering — /forms/:name
  builder.addRoute('/forms', publicFormsRoutes as any, {
    description: 'Public form rendering and submission',
    requiresAuth: false,
    priority: 30
  })

  // API endpoint — /api/forms/:identifier/submit and related
  builder.addRoute('/api/forms', publicFormsRoutes as any, {
    description: 'Forms API for headless frontends',
    requiresAuth: false,
    priority: 30
  })

  // Sidebar menu item
  builder.addMenuItem('Forms', '/admin/forms', {
    icon: 'document-text',
    order: 30,
    permissions: ['forms:manage']
  })

  builder.lifecycle({
    activate: async () => {
      console.info('✅ Forms plugin activated')
    },
    deactivate: async () => {
      console.info('❌ Forms plugin deactivated')
    }
  })

  return builder.build() as Plugin
}

export const formsPlugin = createFormsPlugin()
