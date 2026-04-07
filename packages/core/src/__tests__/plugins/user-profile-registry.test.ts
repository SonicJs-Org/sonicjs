import { describe, it, expect, beforeEach } from 'vitest'
import {
  defineUserProfile,
  getUserProfileConfig,
  getProfileFieldDefaults,
  getRegistrationFields,
  _resetProfileConfig,
  type UserProfileConfig,
} from '../../plugins/core-plugins/user-profiles/user-profile-registry'

describe('User Profile Registry', () => {
  beforeEach(() => {
    _resetProfileConfig()
  })

  const sampleConfig: UserProfileConfig = {
    fields: [
      { name: 'plan', label: 'Subscription Plan', type: 'select', options: ['free', 'pro', 'enterprise'], default: 'free' },
      { name: 'company_size', label: 'Company Size', type: 'number' },
      { name: 'industry', label: 'Industry', type: 'select', options: ['tech', 'healthcare', 'finance'] },
      { name: 'onboarding_completed', label: 'Onboarding', type: 'boolean', default: false },
      { name: 'internal_id', label: 'Internal ID', type: 'string', hidden: true },
    ],
    registrationFields: ['plan', 'company_size'],
  }

  describe('defineUserProfile', () => {
    it('stores config and getUserProfileConfig retrieves it', () => {
      expect(getUserProfileConfig()).toBeNull()
      defineUserProfile(sampleConfig)
      expect(getUserProfileConfig()).toEqual(sampleConfig)
    })

    it('overwrites on double call', () => {
      defineUserProfile(sampleConfig)
      const newConfig: UserProfileConfig = { fields: [{ name: 'x', label: 'X', type: 'string' }] }
      defineUserProfile(newConfig)
      expect(getUserProfileConfig()?.fields).toHaveLength(1)
      expect(getUserProfileConfig()?.fields[0].name).toBe('x')
    })
  })

  describe('getProfileFieldDefaults', () => {
    it('returns defaults for fields that have them', () => {
      defineUserProfile(sampleConfig)
      const defaults = getProfileFieldDefaults()
      expect(defaults).toEqual({ plan: 'free', onboarding_completed: false })
    })

    it('returns empty object when no config', () => {
      expect(getProfileFieldDefaults()).toEqual({})
    })
  })

  describe('getRegistrationFields', () => {
    it('returns only fields listed in registrationFields', () => {
      defineUserProfile(sampleConfig)
      const regFields = getRegistrationFields()
      expect(regFields).toHaveLength(2)
      expect(regFields.map(f => f.name)).toEqual(['plan', 'company_size'])
    })

    it('returns empty array when no config', () => {
      expect(getRegistrationFields()).toEqual([])
    })

    it('returns empty array when registrationFields not set', () => {
      defineUserProfile({ fields: sampleConfig.fields })
      expect(getRegistrationFields()).toEqual([])
    })
  })
})
