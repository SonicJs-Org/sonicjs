import { describe, expect, it } from 'vitest'
import { buildSchemaFieldOptions, resolveSchemaFieldType } from '../../routes/admin-content-field-types'

describe('admin content schema field type resolution', () => {
  it('maps richtext format-backed string fields to richtext', () => {
    expect(
      resolveSchemaFieldType({
        type: 'string',
        format: 'richtext',
      }),
    ).toBe('richtext')
  })

  it('maps media format-backed string fields to media', () => {
    expect(
      resolveSchemaFieldType({
        type: 'string',
        format: 'media',
      }),
    ).toBe('media')
  })

  it('maps date-time format-backed string fields to date', () => {
    expect(
      resolveSchemaFieldType({
        type: 'string',
        format: 'date-time',
      }),
    ).toBe('date')
  })

  it('maps slug fields to slug', () => {
    expect(
      resolveSchemaFieldType({
        type: 'slug',
        format: 'slug',
      }),
    ).toBe('slug')
  })

  it('maps enum-backed string fields to select', () => {
    expect(
      resolveSchemaFieldType({
        type: 'string',
        enum: ['draft', 'published'],
      }),
    ).toBe('select')
  })

  it('preserves explicit editor and structured field types', () => {
    expect(resolveSchemaFieldType({ type: 'markdown' })).toBe('markdown')
    expect(resolveSchemaFieldType({ type: 'quill' })).toBe('quill')
    expect(resolveSchemaFieldType({ type: 'reference' })).toBe('reference')
    expect(resolveSchemaFieldType({ type: 'array' })).toBe('array')
    expect(resolveSchemaFieldType({ type: 'object' })).toBe('object')
  })

  it('builds select options for enum-backed schema fields', () => {
    expect(
      buildSchemaFieldOptions({
        type: 'string',
        enum: ['draft', 'published'],
        enumLabels: ['Draft', 'Published'],
      }),
    ).toMatchObject({
      options: [
        { value: 'draft', label: 'Draft' },
        { value: 'published', label: 'Published' },
      ],
    })
  })
})
