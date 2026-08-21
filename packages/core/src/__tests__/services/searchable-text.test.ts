import { describe, it, expect } from 'vitest'
import { extractSearchableText } from '../../services/searchable-text'

describe('extractSearchableText', () => {
  it('returns plain prose unchanged', () => {
    expect(extractSearchableText('The quick brown fox')).toBe('The quick brown fox')
  })

  it('strips HTML tags', () => {
    expect(extractSearchableText('<p>Hello <b>world</b></p>')).toBe('Hello world')
  })

  it('flattens Quill Delta ops (string inserts only)', () => {
    const delta = {
      ops: [{ insert: 'Hello ' }, { insert: 'world', attributes: { bold: true } }, { insert: { image: 'x.png' } }],
    }
    expect(extractSearchableText(delta)).toBe('Hello world')
  })

  it('harvests string leaves from nested objects', () => {
    const v = { body: 'main text', nested: { deep: 'deep text' } }
    const out = extractSearchableText(v)
    expect(out).toContain('main text')
    expect(out).toContain('deep text')
  })

  it('excludes bare URLs and UUIDs', () => {
    expect(extractSearchableText('https://example.com/page')).toBe('')
    expect(extractSearchableText('550e8400-e29b-41d4-a716-446655440000')).toBe('')
  })

  it('skips structural keys (slug/url) but keeps real prose', () => {
    const v = { slug: 'my-slug', url: 'http://x', title: 'Real Title' }
    const out = extractSearchableText(v)
    expect(out).toContain('Real Title')
    expect(out).not.toContain('my-slug')
  })

  it('returns empty string for null / number / boolean', () => {
    expect(extractSearchableText(null)).toBe('')
    expect(extractSearchableText(42)).toBe('')
    expect(extractSearchableText(true)).toBe('')
  })

  it('collapses whitespace across joined parts', () => {
    expect(extractSearchableText(['  a  ', { x: 'b' }, 'c  '])).toBe('a b c')
  })
})
