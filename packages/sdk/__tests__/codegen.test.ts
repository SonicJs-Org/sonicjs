import { describe, it, expect } from 'vitest'
import { mapFieldType } from '../src/codegen/field-map'
import { emitCollections } from '../src/codegen/emit'
import type { SdkFieldConfig, SdkCollectionConfig } from '../src/codegen/types'

function field(type: SdkFieldConfig['type'], extra?: Partial<SdkFieldConfig>): SdkFieldConfig {
  return { type, ...extra }
}

describe('mapFieldType', () => {
  it.each([
    ['string', 'string'],
    ['email', 'string'],
    ['url', 'string'],
    ['slug', 'string'],
    ['color', 'string'],
    ['richtext', 'string'],
    ['markdown', 'string'],
    ['lexical', 'string'],
    ['textarea', 'string'],
  ] as const)('%s → %s', (type, expected) => {
    expect(mapFieldType(field(type))).toBe(expected)
  })

  it('number → number', () => expect(mapFieldType(field('number'))).toBe('number'))
  it('boolean → boolean', () => expect(mapFieldType(field('boolean'))).toBe('boolean'))
  it('checkbox → boolean', () => expect(mapFieldType(field('checkbox'))).toBe('boolean'))
  it('date → string | number', () => expect(mapFieldType(field('date'))).toBe('string | number'))
  it('datetime → string | number', () => expect(mapFieldType(field('datetime'))).toBe('string | number'))
  it('json → Record<string, unknown>', () => expect(mapFieldType(field('json'))).toBe('Record<string, unknown>'))
  it('reference → string', () => expect(mapFieldType(field('reference'))).toBe('string'))
  it('media → string', () => expect(mapFieldType(field('media'))).toBe('string'))
  it('file → string', () => expect(mapFieldType(field('file'))).toBe('string'))
  it('user → string', () => expect(mapFieldType(field('user'))).toBe('string'))

  it('select with enum → union', () => {
    expect(mapFieldType(field('select', { enum: ['draft', 'published'] }))).toBe("'draft' | 'published'")
  })

  it('select without enum → string', () => {
    expect(mapFieldType(field('select'))).toBe('string')
  })

  it('multiselect with enum → union array', () => {
    expect(mapFieldType(field('multiselect', { enum: ['a', 'b'] }))).toBe("('a' | 'b')[]")
  })

  it('array of string → string[]', () => {
    expect(mapFieldType(field('array', { items: field('string') }))).toBe('string[]')
  })

  it('array without items → unknown[]', () => {
    expect(mapFieldType(field('array'))).toBe('unknown[]')
  })

  it('object with properties → inline interface', () => {
    const result = mapFieldType(field('object', {
      properties: { name: field('string'), age: field('number') },
    }))
    expect(result).toContain('name: string')
    expect(result).toContain('age: number')
  })

  it('object without properties → Record<string, unknown>', () => {
    expect(mapFieldType(field('object'))).toBe('Record<string, unknown>')
  })
})

describe('emitCollections', () => {
  const collections: SdkCollectionConfig[] = [
    {
      name: 'blog_posts',
      displayName: 'Blog Posts',
      schema: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          body: { type: 'richtext' },
          published_at: { type: 'datetime' },
        },
        required: ['title'],
      },
    },
    {
      name: 'team_members',
      displayName: 'Team Members',
      schema: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          role: { type: 'select', enum: ['engineer', 'designer', 'pm'] },
        },
        required: ['name'],
      },
    },
  ]

  it('emits interface per collection + Collections map', () => {
    const output = emitCollections(collections)

    expect(output).toContain('export interface BlogPostsData {')
    expect(output).toContain('  title: string')
    expect(output).toContain('  body?: string')
    expect(output).toContain('  published_at?: string | number')
    expect(output).toContain('export interface TeamMembersData {')
    expect(output).toContain("  role?: 'engineer' | 'designer' | 'pm'")

    expect(output).toContain('export interface Collections {')
    expect(output).toContain('  blog_posts: { data: BlogPostsData }')
    expect(output).toContain('  team_members: { data: TeamMembersData }')
    expect(output).toContain('AUTO-GENERATED')
  })

  it('empty collections emits valid empty Collections interface', () => {
    const output = emitCollections([])
    expect(output).toContain('export interface Collections {')
    expect(output).toContain('}')
  })
})
