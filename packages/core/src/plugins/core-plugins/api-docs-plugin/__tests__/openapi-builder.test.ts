import { describe, it, expect } from 'vitest'
import { buildApiDocsOpenApiSpec } from '../services/openapi-builder'
import type { RouteMetadata } from '../../../../services'

/* eslint-disable @typescript-eslint/no-explicit-any */

const routes: RouteMetadata[] = [
  { method: 'GET', path: '/api/content', description: 'List content', authentication: false, category: 'Content', documented: true },
  { method: 'POST', path: '/api/content/:collection', description: 'Create in collection', authentication: true, category: 'Content', documented: true },
  { method: 'GET', path: '/api/content/:collection/:id', description: 'Get one', authentication: 'unknown', category: 'Content', documented: true },
  { method: 'GET', path: '/files/*', description: 'Serve file', authentication: false, category: 'Media', documented: true },
]

function spec() {
  return buildApiDocsOpenApiSpec(routes, 'https://example.test', '3.0.0-test') as any
}

describe('buildApiDocsOpenApiSpec', () => {
  it('produces an OpenAPI 3.0 document with SonicJS branding (de-branded)', () => {
    const s = spec()
    expect(s.openapi).toBe('3.0.0')
    expect(s.info.title).toBe('SonicJS AI API')
    expect(s.info.version).toBe('3.0.0-test')
    expect(JSON.stringify(s)).not.toContain('Infowall')
    expect(s.servers[0].url).toBe('https://example.test')
    expect(s.components.securitySchemes.bearerAuth).toBeDefined()
  })

  it('converts :param to {param} and trailing /* to /{path}', () => {
    const s = spec()
    expect(s.paths['/api/content/{collection}']).toBeDefined()
    expect(s.paths['/api/content/{collection}/{id}']).toBeDefined()
    expect(s.paths['/files/{path}']).toBeDefined()
    expect(s.paths['/api/content/:collection']).toBeUndefined()
  })

  it('attaches bearer security only to authenticated routes', () => {
    const s = spec()
    expect(s.paths['/api/content/{collection}'].post.security).toEqual([{ bearerAuth: [] }])
    // public and unknown do NOT advertise auth
    expect(s.paths['/api/content'].get.security).toBeUndefined()
    expect(s.paths['/api/content/{collection}/{id}'].get.security).toBeUndefined()
  })

  it('adds a requestBody for POST/PUT/PATCH only', () => {
    const s = spec()
    expect(s.paths['/api/content/{collection}'].post.requestBody).toBeDefined()
    expect(s.paths['/api/content'].get.requestBody).toBeUndefined()
  })

  it('declares path parameters for :param and wildcard routes', () => {
    const s = spec()
    const params = s.paths['/api/content/{collection}/{id}'].get.parameters
    expect(params.map((p: any) => p.name).sort()).toEqual(['collection', 'id'])
    expect(s.paths['/files/{path}'].get.parameters[0]).toMatchObject({ name: 'path', in: 'path', required: true })
  })

  it('builds tags from the categories in use', () => {
    const s = spec()
    const names = s.tags.map((t: any) => t.name)
    expect(names).toContain('Content')
    expect(names).toContain('Media')
  })
})
