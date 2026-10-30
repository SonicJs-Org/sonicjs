import { describe, it, expect } from 'vitest'
import { fieldToJsonSchema, collectionToJsonSchema } from '../schema/field-to-jsonschema'
import type { CollectionSchema } from '../../../../types/collection-config'

describe('fieldToJsonSchema', () => {
  it('maps string-like types to string with constraints', () => {
    expect(fieldToJsonSchema({ type: 'string', minLength: 2, maxLength: 5, pattern: '^a' })).toEqual({
      type: 'string',
      minLength: 2,
      maxLength: 5,
      pattern: '^a',
    })
    expect(fieldToJsonSchema({ type: 'slug' })).toEqual({ type: 'string' })
    expect(fieldToJsonSchema({ type: 'richtext' })).toEqual({ type: 'string' })
    expect(fieldToJsonSchema({ type: 'email' })).toEqual({ type: 'string' })
  })

  it('maps number with min/max', () => {
    expect(fieldToJsonSchema({ type: 'number', min: 1, max: 10 })).toEqual({
      type: 'number',
      minimum: 1,
      maximum: 10,
    })
  })

  it('maps boolean and checkbox', () => {
    expect(fieldToJsonSchema({ type: 'boolean' })).toEqual({ type: 'boolean' })
    expect(fieldToJsonSchema({ type: 'checkbox' })).toEqual({ type: 'boolean' })
  })

  it('maps date/datetime to date-time string', () => {
    expect(fieldToJsonSchema({ type: 'datetime' })).toEqual({ type: 'string', format: 'date-time' })
  })

  it('maps select/radio to enum string', () => {
    expect(fieldToJsonSchema({ type: 'select', enum: ['a', 'b'] })).toEqual({
      type: 'string',
      enum: ['a', 'b'],
    })
  })

  it('maps multiselect to array of enum strings', () => {
    expect(fieldToJsonSchema({ type: 'multiselect', enum: ['a', 'b'] })).toEqual({
      type: 'array',
      items: { type: 'string', enum: ['a', 'b'] },
    })
  })

  it('maps array with nested items', () => {
    expect(fieldToJsonSchema({ type: 'array', items: { type: 'number' } })).toEqual({
      type: 'array',
      items: { type: 'number' },
    })
  })

  it('maps object with nested properties', () => {
    expect(fieldToJsonSchema({ type: 'object', properties: { a: { type: 'string' } } })).toEqual({
      type: 'object',
      properties: { a: { type: 'string' } },
    })
  })

  it('carries title and description through', () => {
    expect(fieldToJsonSchema({ type: 'string', title: 'Name', description: 'Full name' })).toEqual({
      type: 'string',
      title: 'Name',
      description: 'Full name',
    })
  })
})

describe('collectionToJsonSchema', () => {
  const schema: CollectionSchema = {
    type: 'object',
    properties: {
      id: { type: 'string' },
      created_at: { type: 'datetime' },
      title: { type: 'string', required: true },
      body: { type: 'richtext' },
      secret: { type: 'string' },
    },
    required: ['title'],
  }

  it('produces an object schema with all properties by default', () => {
    const out = collectionToJsonSchema(schema)
    expect(out.type).toBe('object')
    expect(Object.keys(out.properties as object)).toEqual(['id', 'created_at', 'title', 'body', 'secret'])
    expect(out.required).toEqual(['title'])
  })

  it('strips system fields when forWrite', () => {
    const out = collectionToJsonSchema(schema, { forWrite: true })
    const keys = Object.keys(out.properties as object)
    expect(keys).not.toContain('id')
    expect(keys).not.toContain('created_at')
    expect(keys).toContain('title')
  })

  it('omits redacted fields', () => {
    const out = collectionToJsonSchema(schema, { redactFields: ['secret'] })
    expect(Object.keys(out.properties as object)).not.toContain('secret')
  })

  it('unions field-level and schema-level required', () => {
    const out = collectionToJsonSchema({
      type: 'object',
      properties: { a: { type: 'string', required: true }, b: { type: 'string' } },
      required: ['b'],
    })
    expect((out.required as string[]).sort()).toEqual(['a', 'b'])
  })

  it('omits required key entirely when nothing is required', () => {
    const out = collectionToJsonSchema({ type: 'object', properties: { a: { type: 'string' } } })
    expect('required' in out).toBe(false)
  })
})
