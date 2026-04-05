/**
 * Tests for the Global Variables resolver
 */

import { describe, it, expect } from 'vitest'
import {
  resolveVariables,
  resolveVariablesInObject,
} from '../../plugins/core-plugins/global-variables-plugin/variable-resolver'

describe('resolveVariables', () => {
  const vars = new Map([
    ['phone_number', '(555) 123-4567'],
    ['company_name', 'Acme Corp'],
    ['opening_hours', 'Mon-Fri 9am-5pm'],
    ['email', 'info@acme.com'],
  ])

  it('should replace a single token', () => {
    expect(resolveVariables('Call us at {phone_number}', vars))
      .toBe('Call us at (555) 123-4567')
  })

  it('should replace multiple tokens', () => {
    expect(resolveVariables('Welcome to {company_name}. Hours: {opening_hours}', vars))
      .toBe('Welcome to Acme Corp. Hours: Mon-Fri 9am-5pm')
  })

  it('should leave unresolved tokens as-is', () => {
    expect(resolveVariables('Contact {unknown_var} at {phone_number}', vars))
      .toBe('Contact {unknown_var} at (555) 123-4567')
  })

  it('should handle empty string', () => {
    expect(resolveVariables('', vars)).toBe('')
  })

  it('should handle string with no tokens', () => {
    expect(resolveVariables('No tokens here', vars)).toBe('No tokens here')
  })

  it('should handle empty variables map', () => {
    expect(resolveVariables('Call {phone_number}', new Map())).toBe('Call {phone_number}')
  })

  it('should not match tokens with uppercase or special chars', () => {
    expect(resolveVariables('{PhoneNumber} and {phone-number}', vars))
      .toBe('{PhoneNumber} and {phone-number}')
  })

  it('should handle adjacent tokens', () => {
    expect(resolveVariables('{company_name}{email}', vars))
      .toBe('Acme Corpinfo@acme.com')
  })
})

describe('resolveVariablesInObject', () => {
  const vars = new Map([
    ['phone_number', '(555) 123-4567'],
    ['company_name', 'Acme Corp'],
  ])

  it('should resolve tokens in nested object values', () => {
    const input = {
      title: 'Contact {company_name}',
      body: '<p>Call us at {phone_number}</p>',
      meta: {
        description: '{company_name} contact page',
      },
    }
    const result = resolveVariablesInObject(input, vars)
    expect(result.title).toBe('Contact Acme Corp')
    expect(result.body).toBe('<p>Call us at (555) 123-4567</p>')
    expect(result.meta.description).toBe('Acme Corp contact page')
  })

  it('should resolve tokens in arrays', () => {
    const input = ['Call {company_name}', 'Phone: {phone_number}']
    const result = resolveVariablesInObject(input, vars)
    expect(result).toEqual(['Call Acme Corp', 'Phone: (555) 123-4567'])
  })

  it('should not modify non-string values', () => {
    const input = { count: 42, active: true, title: '{company_name}' }
    const result = resolveVariablesInObject(input, vars)
    expect(result.count).toBe(42)
    expect(result.active).toBe(true)
    expect(result.title).toBe('Acme Corp')
  })

  it('should handle null/undefined gracefully', () => {
    expect(resolveVariablesInObject(null, vars)).toBeNull()
    expect(resolveVariablesInObject(undefined, vars)).toBeUndefined()
  })

  it('should resolve deeply nested rich text content', () => {
    const input = {
      blocks: [
        {
          type: 'richtext',
          content: '<h1>Welcome to {company_name}</h1><p>Reach us at {phone_number}</p>',
        },
        {
          type: 'text',
          content: 'Simple text for {company_name}',
        },
      ],
    }
    const result = resolveVariablesInObject(input, vars)
    expect(result.blocks[0].content).toBe(
      '<h1>Welcome to Acme Corp</h1><p>Reach us at (555) 123-4567</p>'
    )
    expect(result.blocks[1].content).toBe('Simple text for Acme Corp')
  })
})
