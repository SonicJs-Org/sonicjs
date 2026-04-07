import { describe, it, expect } from 'vitest'
import {
  validateCustomData,
  sanitizeCustomData,
  coerceFieldValue,
  extractCustomFieldsFromForm,
} from '../../plugins/core-plugins/user-profiles/user-profile-service'
import type { UserProfileConfig, ProfileFieldDefinition } from '../../plugins/core-plugins/user-profiles/user-profile-registry'

const testConfig: UserProfileConfig = {
  fields: [
    { name: 'plan', label: 'Plan', type: 'select', options: ['free', 'pro', 'enterprise'], required: true },
    { name: 'company_size', label: 'Company Size', type: 'number', validation: { min: 1, max: 10000 } },
    { name: 'bio', label: 'Bio', type: 'string', validation: { pattern: '^[a-zA-Z0-9 ]+$' } },
    { name: 'active', label: 'Active', type: 'boolean' },
  ],
}

describe('validateCustomData', () => {
  it('passes with valid data', () => {
    const result = validateCustomData({ plan: 'free', company_size: 50 }, testConfig)
    expect(result.valid).toBe(true)
    expect(result.errors).toEqual({})
  })

  it('catches missing required field', () => {
    const result = validateCustomData({ company_size: 50 }, testConfig)
    expect(result.valid).toBe(false)
    expect(result.errors.plan).toBe('Plan is required')
  })

  it('catches invalid select option', () => {
    const result = validateCustomData({ plan: 'invalid' }, testConfig)
    expect(result.valid).toBe(false)
    expect(result.errors.plan).toContain('must be one of')
  })

  it('catches number below min', () => {
    const result = validateCustomData({ plan: 'free', company_size: 0 }, testConfig)
    expect(result.valid).toBe(false)
    expect(result.errors.company_size).toContain('at least 1')
  })

  it('catches number above max', () => {
    const result = validateCustomData({ plan: 'free', company_size: 99999 }, testConfig)
    expect(result.valid).toBe(false)
    expect(result.errors.company_size).toContain('at most 10000')
  })

  it('catches pattern mismatch', () => {
    const result = validateCustomData({ plan: 'free', bio: '<script>alert(1)</script>' }, testConfig)
    expect(result.valid).toBe(false)
    expect(result.errors.bio).toContain('format is invalid')
  })

  it('skips validation for empty optional fields', () => {
    const result = validateCustomData({ plan: 'free' }, testConfig)
    expect(result.valid).toBe(true)
  })
})

describe('sanitizeCustomData', () => {
  it('strips unknown keys', () => {
    const result = sanitizeCustomData({ plan: 'free', unknown_field: 'bad' }, testConfig)
    expect(result).toEqual({ plan: 'free' })
    expect(result).not.toHaveProperty('unknown_field')
  })

  it('sanitizes string values', () => {
    const result = sanitizeCustomData({ bio: '<b>bold</b>' }, testConfig)
    expect(result.bio).toBe('&lt;b&gt;bold&lt;/b&gt;')
  })

  it('passes non-string values through', () => {
    const result = sanitizeCustomData({ company_size: 42, active: true }, testConfig)
    expect(result.company_size).toBe(42)
    expect(result.active).toBe(true)
  })
})

describe('coerceFieldValue', () => {
  it('coerces string to number', () => {
    expect(coerceFieldValue('42', { name: 'x', label: 'X', type: 'number' })).toBe(42)
  })

  it('returns null for invalid number', () => {
    expect(coerceFieldValue('abc', { name: 'x', label: 'X', type: 'number' })).toBeNull()
  })

  it('coerces checkbox values', () => {
    expect(coerceFieldValue('1', { name: 'x', label: 'X', type: 'boolean' })).toBe(true)
    expect(coerceFieldValue('true', { name: 'x', label: 'X', type: 'boolean' })).toBe(true)
    expect(coerceFieldValue('on', { name: 'x', label: 'X', type: 'boolean' })).toBe(true)
    expect(coerceFieldValue('0', { name: 'x', label: 'X', type: 'boolean' })).toBe(false)
  })

  it('returns default for empty value', () => {
    expect(coerceFieldValue('', { name: 'x', label: 'X', type: 'string', default: 'fallback' })).toBe('fallback')
    expect(coerceFieldValue(null, { name: 'x', label: 'X', type: 'string', default: 'fallback' })).toBe('fallback')
  })

  it('returns string as-is for string fields', () => {
    expect(coerceFieldValue('hello', { name: 'x', label: 'X', type: 'string' })).toBe('hello')
  })
})

describe('extractCustomFieldsFromForm', () => {
  it('extracts prefixed custom_ fields from FormData', () => {
    const fd = new FormData()
    fd.set('custom_plan', 'pro')
    fd.set('custom_company_size', '100')
    fd.set('other_field', 'ignored')

    const result = extractCustomFieldsFromForm(fd, testConfig)
    expect(result.plan).toBe('pro')
    expect(result.company_size).toBe(100)
    expect(result).not.toHaveProperty('other_field')
  })

  it('handles boolean fields absent from form (unchecked checkbox)', () => {
    const fd = new FormData()
    fd.set('custom_plan', 'free')
    // custom_active not in form → should be false

    const result = extractCustomFieldsFromForm(fd, testConfig)
    expect(result.active).toBe(false)
  })
})
