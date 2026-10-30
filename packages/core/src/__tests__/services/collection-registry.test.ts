import { describe, it, expect, beforeEach } from 'vitest'
import {
  CollectionRegistry,
  getCollectionRegistry,
  resetCollectionRegistry,
} from '../../services/collection-registry'
import type { CollectionConfig } from '../../types/collection-config'

const makeConfig = (overrides: Partial<CollectionConfig> = {}): CollectionConfig => ({
  name: 'blog_posts',
  displayName: 'Blog Posts',
  schema: { type: 'object', properties: { title: { type: 'string' } } },
  ...overrides,
})

describe('CollectionRegistry', () => {
  let registry: CollectionRegistry

  beforeEach(() => {
    registry = new CollectionRegistry()
  })

  it('registers a collection and lists it', () => {
    registry.register([makeConfig()])
    expect(registry.size()).toBe(1)
    expect(registry.list()).toHaveLength(1)
    expect(registry.list()[0]!.name).toBe('blog_posts')
  })

  it('uses name as id (stable across envs)', () => {
    registry.register([makeConfig({ name: 'products' })])
    const record = registry.getById('products')
    expect(record).toBeDefined()
    expect(record!.id).toBe('products')
    expect(record!.id).toBe(record!.name)
  })

  it('defaults managed=true and isActive=true', () => {
    registry.register([makeConfig()])
    const record = registry.getByName('blog_posts')!
    expect(record.managed).toBe(true)
    expect(record.isActive).toBe(true)
  })

  it('preserves explicit managed=false and isActive=false', () => {
    registry.register([makeConfig({ managed: false, isActive: false })])
    const record = registry.getByName('blog_posts')!
    expect(record.managed).toBe(false)
    expect(record.isActive).toBe(false)
  })

  it('replaces contents on re-register (idempotent for same input)', () => {
    registry.register([makeConfig({ name: 'a' }), makeConfig({ name: 'b' })])
    expect(registry.size()).toBe(2)
    registry.register([makeConfig({ name: 'a' }), makeConfig({ name: 'b' })])
    expect(registry.size()).toBe(2)
  })

  it('replaces contents on re-register (drops removed)', () => {
    registry.register([makeConfig({ name: 'a' }), makeConfig({ name: 'b' })])
    registry.register([makeConfig({ name: 'a' })])
    expect(registry.size()).toBe(1)
    expect(registry.getByName('b')).toBeUndefined()
  })

  it('listActive filters out inactive', () => {
    registry.register([
      makeConfig({ name: 'active1' }),
      makeConfig({ name: 'inactive1', isActive: false }),
      makeConfig({ name: 'active2' }),
    ])
    const active = registry.listActive().map((c) => c.name).sort()
    expect(active).toEqual(['active1', 'active2'])
  })

  it('isActive returns false for unknown collections', () => {
    expect(registry.isActive('nonexistent')).toBe(false)
  })

  it('isActive returns false for inactive collections', () => {
    registry.register([makeConfig({ isActive: false })])
    expect(registry.isActive('blog_posts')).toBe(false)
  })

  it('skips configs without a name', () => {
    registry.register([
      makeConfig({ name: 'good' }),
      { ...makeConfig(), name: '' as any },
    ])
    expect(registry.size()).toBe(1)
    expect(registry.getByName('good')).toBeDefined()
  })

  it('getByName / getById are equivalent for code-defined collections', () => {
    registry.register([makeConfig({ name: 'pages' })])
    expect(registry.getByName('pages')).toBe(registry.getById('pages'))
  })

  it('clear wipes state', () => {
    registry.register([makeConfig()])
    expect(registry.size()).toBe(1)
    registry.clear()
    expect(registry.size()).toBe(0)
  })
})

describe('getCollectionRegistry singleton', () => {
  beforeEach(() => {
    resetCollectionRegistry()
  })

  it('returns the same instance on repeated calls', () => {
    const a = getCollectionRegistry()
    const b = getCollectionRegistry()
    expect(a).toBe(b)
  })

  it('resetCollectionRegistry produces a fresh instance', () => {
    const before = getCollectionRegistry()
    before.register([makeConfig()])
    resetCollectionRegistry()
    const after = getCollectionRegistry()
    expect(after).not.toBe(before)
    expect(after.size()).toBe(0)
  })
})
