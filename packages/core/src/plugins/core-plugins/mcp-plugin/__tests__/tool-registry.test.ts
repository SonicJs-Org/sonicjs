import { describe, it, expect } from 'vitest'
import { buildToolRegistry } from '../tools/registry'
import { resolveMcpConfig } from '../config'
import type { CollectionRecord } from '../../../../services/collection-registry'

function collection(name: string, extra: Partial<CollectionRecord> = {}): CollectionRecord {
  return {
    id: name,
    name,
    displayName: extra.displayName ?? name,
    schema: {
      type: 'object',
      properties: {
        title: { type: 'string', required: true },
        secret: { type: 'string' },
        id: { type: 'string' },
      },
      required: ['title'],
    },
    ...extra,
  } as CollectionRecord
}

const POSTS = collection('posts', { displayName: 'Posts' })
const PAGES = collection('pages', { displayName: 'Pages' })
const COLLECTIONS = new Map([POSTS, PAGES].map((c) => [c.name, c]))

function names(tools: ReturnType<typeof buildToolRegistry>) {
  return tools.map((t) => t.name)
}

describe('buildToolRegistry', () => {
  it('always includes list_collections and read tools per type', () => {
    const cfg = resolveMcpConfig({}, [POSTS, PAGES])
    const tools = buildToolRegistry(cfg, COLLECTIONS, {})
    expect(names(tools)).toEqual(
      expect.arrayContaining(['list_collections', 'list_posts', 'get_posts', 'list_pages', 'get_pages']),
    )
  })

  it('omits search_content unless includeSearch', () => {
    const cfg = resolveMcpConfig({}, [POSTS])
    expect(names(buildToolRegistry(cfg, COLLECTIONS, {}))).not.toContain('search_content')
    expect(names(buildToolRegistry(cfg, COLLECTIONS, { includeSearch: true }))).toContain('search_content')
  })

  it('omits write tools unless includeWrite', () => {
    const cfg = resolveMcpConfig({}, [POSTS])
    expect(names(buildToolRegistry(cfg, COLLECTIONS, {}))).not.toContain('create_posts')
    const withWrite = names(buildToolRegistry(cfg, COLLECTIONS, { includeWrite: true }))
    expect(withWrite).toEqual(
      expect.arrayContaining(['create_posts', 'update_posts', 'publish_posts', 'delete_posts']),
    )
  })

  it('respects per-type write:false even when includeWrite', () => {
    const cfg = resolveMcpConfig({ types: { pages: { read: true, write: false } } }, [POSTS, PAGES])
    const tools = names(buildToolRegistry(cfg, COLLECTIONS, { includeWrite: true }))
    expect(tools).toContain('create_posts')
    expect(tools).not.toContain('create_pages')
    // pages still readable
    expect(tools).toContain('list_pages')
  })

  it('respects per-type read:false', () => {
    const cfg = resolveMcpConfig({ types: { pages: { read: false, write: true } } }, [POSTS, PAGES])
    const tools = names(buildToolRegistry(cfg, COLLECTIONS, { includeWrite: true }))
    expect(tools).not.toContain('list_pages')
    expect(tools).not.toContain('get_pages')
    expect(tools).toContain('create_pages')
  })

  it('strips system + redacted fields from write inputSchema data', () => {
    const cfg = resolveMcpConfig({ redactFields: ['secret'] }, [POSTS])
    const tools = buildToolRegistry(cfg, COLLECTIONS, { includeWrite: true })
    const create = tools.find((t) => t.name === 'create_posts')!
    const dataSchema = (create.inputSchema.properties as any).data
    const keys = Object.keys(dataSchema.properties)
    expect(keys).toContain('title')
    expect(keys).not.toContain('id') // system field stripped
    expect(keys).not.toContain('secret') // redacted
  })

  it('tags each tool with an internal op for routing', () => {
    const cfg = resolveMcpConfig({}, [POSTS])
    const tools = buildToolRegistry(cfg, COLLECTIONS, { includeWrite: true, includeSearch: true })
    expect(tools.find((t) => t.name === 'list_posts')!.op).toBe('list')
    expect(tools.find((t) => t.name === 'create_posts')!.op).toBe('create')
    expect(tools.find((t) => t.name === 'search_content')!.op).toBe('search_content')
  })
})
