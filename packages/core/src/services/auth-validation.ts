/**
 * Auth Validation Service
 *
 * Provides validation schemas for authentication operations
 */

import { z } from 'zod'
import type { D1Database } from '@cloudflare/workers-types'

// In-memory cache for admin existence check (lazy initialization pattern)
let adminExistsCache: boolean | null = null

export interface AuthSettings {
  enablePasswordLogin?: boolean
  enableOAuthLogin?: boolean
  requireEmailVerification?: boolean
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any
}

/**
 * Check if user registration is enabled in the auth plugin settings
 * @param db - D1 database instance
 * @returns true if registration is enabled, false if disabled
 */
export async function isRegistrationEnabled(db: D1Database): Promise<boolean> {
  // Plugin settings live on the plugin's document (type_id='plugin', slug=pluginId) since the
  // document-model migration — the legacy `plugins` table no longer exists on greenfield. The
  // /admin/plugins/core-auth/settings write goes through PluginService.updatePluginSettings (doc model),
  // so the read must come from the same place or "disable registration" silently no-ops.
  try {
    const row = await db
      .prepare(
        "SELECT data FROM documents WHERE slug = 'core-auth' AND type_id = 'plugin' AND tenant_id = 'default' AND is_current_draft = 1 AND deleted_at IS NULL",
      )
      .first() as { data: string } | null
    if (row?.data) {
      const data = typeof row.data === 'string' ? JSON.parse(row.data) : row.data
      const enabled = data?.settings?.registration?.enabled
      return enabled !== false && enabled !== 0
    }
  } catch {
    // fall through to the legacy table for installs that still have it
  }

  // Legacy fallback: the dropped `plugins` table (guarded — absent on greenfield).
  try {
    const plugin = await db.prepare('SELECT settings FROM plugins WHERE id = ?')
      .bind('core-auth')
      .first() as { settings: string } | null
    if (plugin?.settings) {
      // SQLite stores booleans as 0/1, so check for both false and 0.
      const settings = JSON.parse(plugin.settings)
      const enabled = settings?.registration?.enabled
      return enabled !== false && enabled !== 0
    }
  } catch {
    // no legacy table either
  }

  return true // Default to enabled when no setting is found
}

/**
 * Check if this would be the first user registration (bootstrap scenario)
 * The first user should always be allowed to register even if registration is disabled
 * @param db - D1 database instance
 * @returns true if no users exist in the database
 */
export async function isFirstUserRegistration(db: D1Database): Promise<boolean> {
  try {
    const result = await db.prepare('SELECT COUNT(*) as count FROM auth_user').first() as { count: number } | null
    return result?.count === 0
  } catch {
    return false // Default to not first user on error
  }
}

/**
 * Check if an admin user exists in the database (with in-memory caching)
 * Uses lazy initialization - only queries DB on first call, then caches result
 * @param db - D1 database instance
 * @returns true if an admin user exists
 */
export async function checkAdminUserExists(db: D1Database): Promise<boolean> {
  // Return cached value if already checked
  if (adminExistsCache !== null) {
    return adminExistsCache
  }

  try {
    const result = await db.prepare('SELECT id FROM auth_user WHERE role = ?')
      .bind('admin')
      .first()
    adminExistsCache = !!result
    return adminExistsCache
  } catch {
    // On error (e.g., table doesn't exist yet), assume no admin exists
    return false
  }
}

/**
 * Set the admin exists cache to true
 * Call this after successfully creating the first admin user
 */
export function setAdminExists(): void {
  adminExistsCache = true
}

/**
 * Reset the admin exists cache (for testing purposes)
 */
export function resetAdminExistsCache(): void {
  adminExistsCache = null
}

/**
 * Auth Validation Service
 * Provides dynamic validation schemas for registration based on database settings
 */
/**
 * Email schema. Zod's `.email()` already rejects the common malformed shapes
 * (spaces, double-quoted local parts, consecutive dots, leading dots, commas),
 * but it *accepts* domain labels that begin or end with a hyphen (e.g.
 * `user@example-.com`), which are invalid per RFC 1035. The refine closes that
 * gap so registration validation matches stricter CMS auth suites.
 */
export const emailSchema = z
  .string()
  .email('Valid email is required')
  .refine(
    (value) => {
      const at = value.lastIndexOf('@')
      if (at < 0) return false
      const domain = value.slice(at + 1)
      // No domain label may start or end with a hyphen.
      return domain.split('.').every((label) => label.length > 0 && !label.startsWith('-') && !label.endsWith('-'))
    },
    { message: 'Valid email is required' }
  )

const baseRegistrationSchema = z.object({
  email: emailSchema,
  password: z.string().min(8, 'Password must be at least 8 characters'),
  firstName: z.string().min(1, 'First name is required').optional(),
  lastName: z.string().min(1, 'Last name is required').optional()
})

export type RegistrationSchema = typeof baseRegistrationSchema
export type RegistrationData = z.infer<RegistrationSchema>

export const authValidationService = {
  /**
   * Build registration schema dynamically based on auth settings
   * For now, returns a static schema with standard fields
   */
  async buildRegistrationSchema(_db: D1Database): Promise<RegistrationSchema> {
    // TODO: Load settings from database to make fields optional/required dynamically
    // For now, use a static schema with common registration fields
    return baseRegistrationSchema
  },

  /**
   * Generate default values for optional fields
   */
  generateDefaultValue(field: string, data: any): string {
    switch (field) {
      case 'firstName':
        return 'User'
      case 'lastName':
        return data.email ? data.email.split('@')[0] : 'Account'
      default:
        return ''
    }
  }
}
