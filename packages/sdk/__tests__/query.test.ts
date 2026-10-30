import { describe, it, expect } from 'vitest'
import { serializeQuery } from '../src/query'

function decode(qs: string): Record<string, string[]> {
  const out: Record<string, string[]> = {}
  for (const part of qs.split('&')) {
    if (!part) continue
    const [k, v] = part.split('=').map(decodeURIComponent) as [string, string]
    out[k] = [...(out[k] ?? []), v]
  }
  return out
}

describe('serializeQuery', () => {
  it('serializes simple scalars', () => {
    const qs = serializeQuery({ limit: 10, offset: 20, status: 'published' })
    const p = decode(qs)
    expect(p['limit']).toEqual(['10'])
    expect(p['offset']).toEqual(['20'])
    expect(p['status']).toEqual(['published'])
  })

  it('serializes arrays as CSV (fields, include)', () => {
    const qs = serializeQuery({ fields: ['id', 'title', 'data.excerpt'] })
    const p = decode(qs)
    expect(p['fields']).toEqual(['id,title,data.excerpt'])
  })

  it('where[field][op]=value for object condition', () => {
    const qs = serializeQuery({ where: { collectionId: { equals: 'posts' } } })
    const p = decode(qs)
    expect(p['where[collectionId][equals]']).toEqual(['posts'])
  })

  it('where[field][]=v for array condition (in operator)', () => {
    const qs = serializeQuery({ where: { status: { in: ['draft', 'published'] } } })
    const p = decode(qs)
    expect(p['where[status][]']).toEqual(['draft', 'published'])
  })

  it('where[field][]=v for shorthand array', () => {
    const qs = serializeQuery({ where: { tags: ['react', 'typescript'] } })
    const p = decode(qs)
    expect(p['where[tags][]']).toEqual(['react', 'typescript'])
  })

  it('shorthand scalar becomes [equals]', () => {
    const qs = serializeQuery({ where: { status: 'published' } })
    const p = decode(qs)
    expect(p['where[status][equals]']).toEqual(['published'])
  })

  it('filter[field]=value for documents filter', () => {
    const qs = serializeQuery({ filter: { department: 'Engineering', region: 'US-East' } })
    const p = decode(qs)
    expect(p['filter[department]']).toEqual(['Engineering'])
    expect(p['filter[region]']).toEqual(['US-East'])
  })

  it('facet[field]=value for documents facet', () => {
    const qs = serializeQuery({ facet: { tag: 'react' } })
    const p = decode(qs)
    expect(p['facet[tag]']).toEqual(['react'])
  })

  it('cursor expands to cursor_updated_at + cursor_id', () => {
    const qs = serializeQuery({ cursor: { updatedAt: 1700001, id: 'abc-123' } })
    const p = decode(qs)
    expect(p['cursor_updated_at']).toEqual(['1700001'])
    expect(p['cursor_id']).toEqual(['abc-123'])
  })

  it('resolveVariables maps to resolve_variables', () => {
    const qs = serializeQuery({ resolveVariables: true })
    const p = decode(qs)
    expect(p['resolve_variables']).toEqual(['true'])
  })

  it('undefined and null values are omitted', () => {
    const qs = serializeQuery({ limit: undefined, status: null as unknown as string, sort: 'created_at' })
    const p = decode(qs)
    expect(p['limit']).toBeUndefined()
    expect(p['status']).toBeUndefined()
    expect(p['sort']).toEqual(['created_at'])
  })

  it('empty object returns empty string', () => {
    expect(serializeQuery({})).toBe('')
  })

  it('JSON path field in where', () => {
    const qs = serializeQuery({ where: { 'data.title': { contains: 'hello' } } })
    const p = decode(qs)
    expect(p['where[data.title][contains]']).toEqual(['hello'])
  })
})
