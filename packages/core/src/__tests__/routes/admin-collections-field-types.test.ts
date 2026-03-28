import { describe, expect, it } from 'vitest'
import { normalizeFieldType } from '../../routes/admin-collections-field-types'

describe('admin collection field type normalization', () => {
  it('normalizes markdown aliases to markdown', () => {
    expect(normalizeFieldType('markdown')).toBe('markdown')
    expect(normalizeFieldType('mdxeditor')).toBe('markdown')
    expect(normalizeFieldType('easymde')).toBe('markdown')
  })

  it('normalizes tinymce to richtext for collection editor round-tripping', () => {
    expect(normalizeFieldType('tinymce')).toBe('richtext')
  })

  it('leaves other field types unchanged', () => {
    expect(normalizeFieldType('richtext')).toBe('richtext')
    expect(normalizeFieldType('quill')).toBe('quill')
    expect(normalizeFieldType('reference')).toBe('reference')
  })
})
