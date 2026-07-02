// @ts-nocheck
// Route-level integration test for the MCP endpoint over real SQLite (R10: unit/mock
// tests can't prove SQL, batch atomicity, generated columns, or ACL). Mounts the real
// createMcpRoutes() on a Hono app and drives it with JSON-RPC, exercising the full
// create → list → publish → get → update → delete round-trip plus auth + ACL gates.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../../../../__tests__/utils/d1-sqlite'
import { bootstrapDocumentTypes, autoRegisterCollectionDocumentTypes } from '../../../../services/document-types-seed'
import { getCollectionRegistry, resetCollectionRegistry } from '../../../../services/collection-registry'
import { createMcpRoutes } from '../routes/mcp'

const SCHEMA = {
  type: 'object',
  properties: {
    title: { type: 'string', title: 'Title', required: true },
    slug: { type: 'string', title: 'Slug' },
    body: { type: 'string', title: 'Body' },
  },
  required: ['title'],
}

function buildApp(db: any) {
  const app = new Hono()
  app.use('*', async (c: any, next: any) => {
    c.env = { DB: db }
    // Simulate what the app-wide apiKeyAuthMiddleware does: set c.get('user') from a
    // resolved key. A missing role header models an unauthenticated request.
    const role = c.req.header('x-test-role')
    if (role) c.set('user', { userId: 'u1', email: 'a@b.c', role })
    await next()
  })
  app.route('/mcp', createMcpRoutes({}))
  return app
}

let seq = 0
const nextId = () => ++seq

// role: a string sets the x-test-role header (authenticated); `null` sends no header
// (unauthenticated). Note: passing `undefined` would trigger the default, so use `null`.
async function rpc(app: any, method: string, params?: any, role: string | null = 'admin') {
  const res = await app.request('/mcp', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(role ? { 'x-test-role': role } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: nextId(), method, params }),
  })
  return { status: res.status, body: await res.json() }
}

// tools/call helper — returns the parsed tool result (or the raw envelope on error).
async function call(app: any, name: string, args: any = {}, role = 'admin') {
  const { body } = await rpc(app, 'tools/call', { name, arguments: args }, role)
  return body
}
const parseContent = (envelope: any) => JSON.parse(envelope.result.content[0].text)

describe('mcp plugin — endpoint over real SQLite', () => {
  let db: any
  let app: any

  beforeEach(async () => {
    db = createTestD1()
    getCollectionRegistry().register([
      {
        name: 'mcp_post',
        displayName: 'MCP Posts',
        description: 'Test collection',
        schema: SCHEMA,
        access: {
          admin: ['read', 'create', 'update', 'delete', 'publish', 'manage'],
          viewer: ['read'],
        },
      },
    ])
    await bootstrapDocumentTypes(db)
    await autoRegisterCollectionDocumentTypes(db)
    app = buildApp(db)
  })

  afterEach(() => {
    db.close()
    resetCollectionRegistry()
  })

  it('initialize returns the handshake', async () => {
    const { body } = await rpc(app, 'initialize')
    expect(body.result.serverInfo.name).toBe('sonicjs-mcp')
    expect(body.result.capabilities).toHaveProperty('tools')
    expect(body.result.capabilities).toHaveProperty('resources')
  })

  it('rejects an unauthenticated request with -32001', async () => {
    const { body } = await rpc(app, 'tools/list', undefined, null)
    expect(body.error.code).toBe(-32001)
  })

  it('tools/list advertises read + write tools for the exposed type', async () => {
    const { body } = await rpc(app, 'tools/list')
    const names = body.result.tools.map((t: any) => t.name)
    expect(names).toEqual(
      expect.arrayContaining([
        'list_collections',
        'list_mcp_post',
        'get_mcp_post',
        'create_mcp_post',
        'update_mcp_post',
        'publish_mcp_post',
        'delete_mcp_post',
      ]),
    )
    // search_content is phase-gated off in v1.
    expect(names).not.toContain('search_content')
  })

  it('runs a full create → publish → get → update → delete round-trip', async () => {
    // create as a draft
    const created = parseContent(await call(app, 'create_mcp_post', { title: 'Hello', slug: 'hello', data: { body: 'world' } }))
    const rootId = created.rootId
    expect(rootId).toBeTruthy()
    expect(created.isPublished).toBe(false)

    // not yet visible as published
    expect(parseContent(await call(app, 'list_mcp_post', { status: 'published' }))).toHaveLength(0)
    // visible as a draft
    const drafts = parseContent(await call(app, 'list_mcp_post', { status: 'draft' }))
    expect(drafts.map((d: any) => d.rootId)).toContain(rootId)

    // publish it
    const published = parseContent(await call(app, 'publish_mcp_post', { id: rootId }))
    expect(published.isPublished).toBe(true)

    // now visible as published
    const pub = parseContent(await call(app, 'list_mcp_post', { status: 'published' }))
    expect(pub.map((d: any) => d.rootId)).toContain(rootId)

    // get by root id returns the published payload
    const got = parseContent(await call(app, 'get_mcp_post', { id: rootId }))
    expect(got.data.body).toBe('world')

    // update merges data into a new draft (published row unchanged until republish)
    parseContent(await call(app, 'update_mcp_post', { id: rootId, data: { body: 'updated' } }))
    const draftAfter = parseContent(await call(app, 'list_mcp_post', { status: 'draft' })).find((d: any) => d.rootId === rootId)
    expect(draftAfter.data.body).toBe('updated')

    // delete (soft) removes it from published + draft listings
    const del = parseContent(await call(app, 'delete_mcp_post', { id: rootId }))
    expect(del.deleted).toBe(true)
    expect(parseContent(await call(app, 'list_mcp_post', { status: 'published' }))).toHaveLength(0)
    expect(parseContent(await call(app, 'list_mcp_post', { status: 'draft' })).some((d: any) => d.rootId === rootId)).toBe(false)
  })

  it('enforces ACL — a viewer cannot create', async () => {
    const res = await call(app, 'create_mcp_post', { title: 'Nope' }, 'viewer')
    expect(res.result.isError).toBe(true)
    expect(res.result.content[0].text).toMatch(/denied/i)
    // and nothing was written
    expect(parseContent(await call(app, 'list_mcp_post', { status: 'draft' }, 'admin'))).toHaveLength(0)
  })

  it('get on a missing document returns an MCP tool error, not a crash', async () => {
    const res = await call(app, 'get_mcp_post', { id: 'does-not-exist' })
    expect(res.result.isError).toBe(true)
    expect(res.result.content[0].text).toMatch(/not found/i)
  })

  it('unknown tool → method not found (-32601)', async () => {
    const { body } = await rpc(app, 'tools/call', { name: 'no_such_tool' })
    expect(body.error.code).toBe(-32601)
  })

  it('list_collections reports the exposed type + access flags', async () => {
    const cols = parseContent(await call(app, 'list_collections'))
    const post = cols.find((c: any) => c.typeId === 'mcp_post')
    expect(post).toMatchObject({ displayName: 'MCP Posts', read: true, write: true })
  })

  it('resources/read returns JSON Schema for a type', async () => {
    const { body } = await rpc(app, 'resources/read', { uri: 'sonicjs://collections/mcp_post/schema' })
    const schema = JSON.parse(body.result.contents[0].text)
    expect(schema.type).toBe('object')
    expect(schema.properties).toHaveProperty('title')
  })
})
