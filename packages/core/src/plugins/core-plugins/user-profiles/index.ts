/**
 * User Profiles Plugin — Payload-shaped port.
 *
 * Configurable custom profile fields for users. defineUserProfile() at app
 * boot declares custom fields stored as JSON in auth_user_profiles.data and
 * rendered in the admin UI.
 *
 * API Routes:
 *   GET  /api/user-profiles/schema     → Public field definitions
 *   GET  /api/user-profiles/:userId    → Get custom data for a user
 *   PUT  /api/user-profiles/:userId    → Update custom data for a user
 */

import type { Context } from 'hono'
import { Hono } from 'hono'
import type { Bindings, Variables } from '../../../app'
import { definePlugin } from '../../sdk/define-plugin'
import { requireAuth } from '../../../middleware'
import { getUserProfileConfig } from './user-profile-registry'
import {
  getCustomData,
  saveCustomData,
  validateCustomData,
  sanitizeCustomData,
} from './user-profile-service'

type AppEnv = { Bindings: Bindings; Variables: Variables }

/**
 * Authorize access to a user's profile data: the signed-in user may act on their
 * OWN profile; admins may act on any. Returns true when allowed.
 * (Runs after requireAuth(), so c.get('user') is present.)
 */
function canAccessProfile(
  c: Context<AppEnv>,
  targetUserId: string | undefined,
): targetUserId is string {
  if (!targetUserId) return false
  const user = c.get('user')
  if (!user) return false
  return user.userId === targetUserId || user.role === 'admin'
}

const api = new Hono<AppEnv>()

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

api.get('/:userId', requireAuth(), async (c) => {
  const db = c.env.DB
  if (!db) return c.json({ error: 'Database not available' }, 500)

  const userId = c.req.param('userId')
  // A user may read only their own profile; admins may read any.
  if (!canAccessProfile(c, userId)) {
    return c.json({ error: 'Forbidden' }, 403)
  }
  const data = await getCustomData(db, userId)
  return c.json({ userId, customData: data })
})

api.put('/:userId', requireAuth(), async (c) => {
  const db = c.env.DB
  if (!db) return c.json({ error: 'Database not available' }, 500)

  const config = getUserProfileConfig()
  if (!config) {
    return c.json({ error: 'No profile schema configured' }, 400)
  }

  const userId = c.req.param('userId')
  // A user may update only their own profile; admins may update any.
  if (!canAccessProfile(c, userId)) {
    return c.json({ error: 'Forbidden' }, 403)
  }
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

export const userProfilesPlugin = definePlugin({
  id: 'user-profiles',
  version: '1.0.0',
  name: 'User Profiles',
  description: 'Configurable custom profile fields for users.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  register(app) {
    app.route('/api/user-profiles', api)
  },

  activate: async () => console.info('[SonicJS] User Profiles plugin activated'),
  deactivate: async () => console.info('[SonicJS] User Profiles plugin deactivated'),
})

export function createUserProfilesPlugin() {
  return userProfilesPlugin
}

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

export {
  readProfileData,
  writeProfileData,
  USER_PROFILE_TYPE_ID,
  type ProfileDocumentData,
  type ProfileTypedFields,
} from './user-profile-document'
