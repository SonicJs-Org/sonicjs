import { describe, it, expect } from 'vitest'
import { resolveMcpConfig } from '../config'
import type { CollectionRecord } from '../../../../services/collection-registry'

function col(name: string, displayName?: string): CollectionRecord {
  return {
    id: name,
    name,
    displayName: displayName ?? name,
    schema: { type: 'object', properties: {} },
  } as CollectionRecord
}

const ALL = [col('posts', 'Posts'), col('pages', 'Pages'), col('products', 'Products')]

describe('resolveMcpConfig', () => {
  it('exposes every active collection by default with read+write', () => {
    const r = resolveMcpConfig({}, ALL)
    expect(r.types.map((t) => t.typeId)).toEqual(['posts', 'pages', 'products'])
    expect(r.types.every((t) => t.read && t.write)).toBe(true)
    expect(r.listLimit).toBe(50)
    expect(r.redactFields).toEqual([])
  })

  it('applies the expose allowlist', () => {
    const r = resolveMcpConfig({ expose: ['posts'] }, ALL)
    expect(r.types.map((t) => t.typeId)).toEqual(['posts'])
  })

  it('applies per-type read/write overrides', () => {
    const r = resolveMcpConfig({ types: { pages: { read: true, write: false } } }, ALL)
    const pages = r.types.find((t) => t.typeId === 'pages')!
    expect(pages.write).toBe(false)
    expect(pages.read).toBe(true)
  })

  it('carries redactFields and listLimit through', () => {
    const r = resolveMcpConfig({ redactFields: ['a', 'b'], listLimit: 10 }, ALL)
    expect(r.redactFields).toEqual(['a', 'b'])
    expect(r.listLimit).toBe(10)
  })

  it('resolves display names from the registry', () => {
    const r = resolveMcpConfig({ expose: ['products'] }, ALL)
    expect(r.types[0]!.displayName).toBe('Products')
  })

  it('caps listLimit at 200', () => {
    expect(() => resolveMcpConfig({ listLimit: 999 }, ALL)).toThrow()
  })
})
