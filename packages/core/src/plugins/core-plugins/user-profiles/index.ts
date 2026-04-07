/**
 * User Profiles Plugin
 *
 * Configurable custom profile fields for users.
 * Developers call defineUserProfile() at app boot to declare custom fields
 * that are stored as JSON in user_profiles.data and rendered in the admin UI.
 *
 * API Routes:
 *   GET  /api/user-profiles/schema     → Public field definitions
 *   GET  /api/user-profiles/:userId    → Get custom data for a user (auth required)
 *   PUT  /api/user-profiles/:userId    → Update custom data for a user (auth required)
 */

import { Hono } from 'hono'
import { PluginBuilder } from '../../sdk/plugin-builder'
import type { Plugin } from '../../types'
import { getUserProfileConfig } from './user-profile-registry'
import {
  getCustomData,
  saveCustomData,
  validateCustomData,
  sanitizeCustomData,
  extractCustomFieldsFromForm,
} from './user-profile-service'
import { renderCustomProfileSection } from './user-profile-renderer'

export function createUserProfilesPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: 'user-profiles',
    version: '1.0.0-beta.1',
    description: 'Configurable custom profile fields for users',
  })

  builder.metadata({
    author: {
      name: 'SonicJS Team',
      email: 'team@sonicjs.com',
    },
    license: 'MIT',
    compatibility: '^2.0.0',
  })

  // ==================== API Routes ====================

  const api = new Hono()

  // GET /api/user-profiles/schema — public schema endpoint
  api.get('/schema', (c) => {
    const config = getUserProfileConfig()
    if (!config) {
      return c.json({ fields: [], registrationFields: [] })
    }
    return c.json({
      fields: config.fields
        .filter(f => !f.hidden)
        .map(f => ({
          name: f.name,
          label: f.label,
          type: f.type,
          options: f.options,
          required: f.required || false,
          placeholder: f.placeholder,
          helpText: f.helpText,
          default: f.default,
          validation: f.validation,
        })),
      registrationFields: config.registrationFields || [],
    })
  })

  // GET /api/user-profiles/:userId — get custom data
  api.get('/:userId', async (c) => {
    const db = (c.env as any)?.DB || (c as any).db
    if (!db) return c.json({ error: 'Database not available' }, 500)

    const userId = c.req.param('userId')
    const data = await getCustomData(db, userId)
    return c.json({ userId, customData: data })
  })

  // PUT /api/user-profiles/:userId — update custom data
  api.put('/:userId', async (c) => {
    const db = (c.env as any)?.DB || (c as any).db
    if (!db) return c.json({ error: 'Database not available' }, 500)

    const config = getUserProfileConfig()
    if (!config) {
      return c.json({ error: 'No profile schema configured' }, 400)
    }

    const userId = c.req.param('userId')
    const body = await c.req.json()
    const customData = body.customData || body

    const sanitized = sanitizeCustomData(customData, config)
    const validation = validateCustomData(sanitized, config)
    if (!validation.valid) {
      return c.json({ error: 'Validation failed', errors: validation.errors }, 400)
    }

    await saveCustomData(db, userId, sanitized)
    return c.json({ success: true })
  })

  builder.addRoute('/api/user-profiles', api, {
    description: 'Custom user profile fields API',
    requiresAuth: false,
    priority: 100,
  })

  builder.lifecycle({
    activate: async () => {
      console.info('[SonicJS] User Profiles plugin activated')
    },
    deactivate: async () => {
      console.info('[SonicJS] User Profiles plugin deactivated')
    },
  })

  return builder.build() as Plugin
}

export const userProfilesPlugin = createUserProfilesPlugin()

// Re-export public API
export {
  defineUserProfile,
  getUserProfileConfig,
  getProfileFieldDefaults,
  getRegistrationFields,
  type ProfileFieldDefinition,
  type UserProfileConfig,
} from './user-profile-registry'

export {
  getCustomData,
  saveCustomData,
  validateCustomData,
  sanitizeCustomData,
  extractCustomFieldsFromForm,
} from './user-profile-service'

export { renderCustomProfileSection } from './user-profile-renderer'
