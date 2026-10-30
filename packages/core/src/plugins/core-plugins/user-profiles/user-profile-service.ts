/**
 * User Profile Service
 *
 * Handles reading, writing, validation, and sanitization of custom profile data.
 */

import { sanitizeInput } from '../../../utils/sanitize'
import {
  getUserProfileConfig,
  getProfileFieldDefaults,
  type ProfileFieldDefinition,
  type UserProfileConfig,
} from './user-profile-registry'

export function validateCustomData(
  data: Record<string, any>,
  config: UserProfileConfig
): { valid: boolean; errors: Record<string, string> } {
  const errors: Record<string, string> = {}

  for (const field of config.fields) {
    const value = data[field.name]

    if (field.required && (value === undefined || value === null || value === '')) {
      errors[field.name] = `${field.label} is required`
      continue
    }

    if (value === undefined || value === null || value === '') continue

    if (field.type === 'number' && typeof value !== 'number') {
      errors[field.name] = `${field.label} must be a number`
    }
    if (field.type === 'select' && field.options && !field.options.includes(value)) {
      errors[field.name] = `${field.label} must be one of: ${field.options.join(', ')}`
    }
    if (field.type === 'boolean' && typeof value !== 'boolean') {
      errors[field.name] = `${field.label} must be true or false`
    }
    if (field.validation?.min !== undefined && typeof value === 'number' && value < field.validation.min) {
      errors[field.name] = `${field.label} must be at least ${field.validation.min}`
    }
    if (field.validation?.max !== undefined && typeof value === 'number' && value > field.validation.max) {
      errors[field.name] = `${field.label} must be at most ${field.validation.max}`
    }
    if (field.validation?.pattern && typeof value === 'string' && !new RegExp(field.validation.pattern).test(value)) {
      errors[field.name] = `${field.label} format is invalid`
    }
  }

  return { valid: Object.keys(errors).length === 0, errors }
}

export function sanitizeCustomData(
  data: Record<string, any>,
  config: UserProfileConfig
): Record<string, any> {
  const result: Record<string, any> = {}
  const knownNames = new Set(config.fields.map(f => f.name))

  for (const [key, value] of Object.entries(data)) {
    if (!knownNames.has(key)) continue
    if (typeof value === 'string') {
      result[key] = sanitizeInput(value)
    } else {
      result[key] = value
    }
  }

  return result
}

export function coerceFieldValue(raw: string | null | undefined, field: ProfileFieldDefinition): any {
  if (raw === null || raw === undefined || raw === '') {
    return field.default ?? null
  }

  switch (field.type) {
    case 'number':
      const num = Number(raw)
      return isNaN(num) ? null : num
    case 'boolean':
    case 'checkbox':
      return raw === '1' || raw === 'true' || raw === 'on'
    case 'date':
    case 'datetime':
      const ts = new Date(raw).getTime()
      return isNaN(ts) ? null : ts
    default:
      return raw
  }
}

export function extractCustomFieldsFromForm(
  formData: FormData,
  config: UserProfileConfig
): Record<string, any> {
  const result: Record<string, any> = {}
  for (const field of config.fields) {
    const raw = formData.get(`custom_${field.name}`)?.toString()
    // For boolean/checkbox, absence means false
    if (raw === null || raw === undefined) {
      if (field.type === 'boolean' || field.type === 'checkbox') {
        result[field.name] = false
      }
      continue
    }
    result[field.name] = coerceFieldValue(raw, field)
  }
  return result
}

// Custom profile fields are stored under `data.custom` of the user's
// `user_profile` document (see user-profile-document.ts). These thin wrappers
// preserve the original custom-only contract for existing callers.
import { readProfileData, writeProfileData } from './user-profile-document'

export async function getCustomData(db: any, userId: string): Promise<Record<string, any>> {
  return (await readProfileData(db, userId)).custom
}

export async function saveCustomData(
  db: any,
  userId: string,
  newData: Record<string, any>
): Promise<void> {
  await writeProfileData(db, userId, { custom: newData })
}
