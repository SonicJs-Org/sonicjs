/**
 * User Profile Config Registry
 *
 * Global singleton storing developer-defined custom profile field definitions.
 * Set once at app boot via defineUserProfile(), queried by routes and templates.
 */

import type { FieldType } from '../../../types/collection-config'

export interface ProfileFieldDefinition {
  name: string
  label: string
  type: FieldType
  options?: string[]
  default?: any
  required?: boolean
  placeholder?: string
  helpText?: string
  hidden?: boolean
  fields?: ProfileFieldDefinition[]
  validation?: {
    min?: number
    max?: number
    pattern?: string
  }
}

export interface UserProfileConfig {
  fields: ProfileFieldDefinition[]
  registrationFields?: string[]
}

let _profileConfig: UserProfileConfig | null = null

export function defineUserProfile(config: UserProfileConfig): void {
  if (_profileConfig) {
    console.warn('[SonicJS] defineUserProfile called multiple times — overwriting previous config')
  }
  _profileConfig = config
}

export function getUserProfileConfig(): UserProfileConfig | null {
  return _profileConfig
}

export function getProfileFieldDefaults(): Record<string, any> {
  if (!_profileConfig) return {}
  const defaults: Record<string, any> = {}
  for (const field of _profileConfig.fields) {
    if (field.default !== undefined) {
      defaults[field.name] = field.default
    }
  }
  return defaults
}

export function getRegistrationFields(): ProfileFieldDefinition[] {
  if (!_profileConfig) return []
  const regFieldNames = _profileConfig.registrationFields || []
  return _profileConfig.fields.filter(f => regFieldNames.includes(f.name))
}

/** Reset state — for tests only */
export function _resetProfileConfig(): void {
  _profileConfig = null
}
