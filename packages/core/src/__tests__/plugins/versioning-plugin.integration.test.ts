// @ts-nocheck
/**
 * Integration tests for the versioning plugin routes.
 *
 * Mounts the versioningPlugin's sub-app on a Hono app backed by a real-SQLite D1 shim.
 * Auth middleware is stubbed so every request is treated as an authenticated admin.
 * Tests cover:
 *   1. GET /admin/versioning/:rootId — returns 200 and lists ≥2 versions for a versioned type
 *   2. POST /admin/versioning/:rootId/restore/:versionNumber — restores an older version's data
 *   3. Non-existent doc → 404
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'
import { DocumentTypeRegistry } from '../../services/document-type-registry'
import { DocumentsService } from '../../services/documents'

// Stub auth middleware — every request is treated as authenticated admin
import { vi } from 'vitest'
vi.mock('../../middleware/auth', () => ({
  requireAuth: () => async (_c: any, next: any) => next(),
  requireRole: () => async (_c: any, next: any) => next(),
}))

import routes from '../../plugins/core-plugins/versioning-plugin/routes'

const TENANT = 'default'
const VERSIONED_TYPE_ID = 'test_versioned_article'

function buildApp(db: any) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    ;(c as any).env = { DB: db }
    c.set('user', { userId: 'u1', email: 'admin@test.com', role: 'admin' })
    c.set('tenantId', TENANT)
    await next()
  })
  app.route('/admin/versioning', routes)
  return app
}

describe('versioning-plugin routes — integration (real SQLite)', () => {
  let db: any
  let app: any

  beforeEach(async () => {
    db = createTestD1()
    await bootstrapDocumentTypes(db)

    // Register a versioned document type for tests
    const registry = new DocumentTypeRegistry(db)
    await registry.register({
      id: VERSIONED_TYPE_ID,
      name: VERSIONED_TYPE_ID,
      displayName: 'Test Versioned Article',
      description: 'Test document type with versioning enabled',
      source: 'system',
      schema: { type: 'object' },
      settings: {
        versioning: true,
        maxVersionsPerRoot: 20,
        baseGrants: {
          admin: ['read', 'create', 'update', 'delete', 'publish', 'manage'],
          editor: ['read', 'create', 'update', 'publish'],
        },
      },
      queryableFields: [],
    })

    app = buildApp(db)
  })

  afterEach(() => db.close())

  function makeDocService() {
    return new DocumentsService(db, {
      queryableFields: [],
      typeSchemaVersion: 1,
      maxVersionsPerRoot: 20,
      tenantId: TENANT,
      versioning: true,
    })
  }

  // ── Test 1: GET /:rootId returns 200 and lists ≥2 versions ──────────────────
  it('returns 200 and lists ≥2 versions for a versioned type', async () => {
    const svc = makeDocService()

    // Create initial document (version 1)
    const doc = await svc.create({
      typeId: VERSIONED_TYPE_ID,
      tenantId: TENANT,
      locale: 'default',
      title: 'First Version',
      data: { body: 'original content' },
    }, 'u1')

    const rootId = doc.rootId

    // Save second draft (version 2)
    await svc.saveDraft(rootId, { data: { body: 'updated content' }, title: 'Second Version', slug: null }, 'u1')

    const res = await app.request(`/admin/versioning/${rootId}`)
    expect(res.status).toBe(200)

    const html = await res.text()
    // Should contain version numbers
    expect(html).toContain('v1')
    expect(html).toContain('v2')
  })

  // ── Test 2: POST /:rootId/restore/:versionNumber restores data ──────────────
  it('restores an older version as a new current draft', async () => {
    const svc = makeDocService()

    // Create v1 with specific content
    const doc = await svc.create({
      typeId: VERSIONED_TYPE_ID,
      tenantId: TENANT,
      locale: 'default',
      title: 'Original Title',
      data: { body: 'original body text' },
    }, 'u1')

    const rootId = doc.rootId

    // Save a new draft (v2) overwriting the data
    await svc.saveDraft(rootId, { data: { body: 'completely different text' }, title: 'Changed Title', slug: null }, 'u1')

    // Verify v2 is now the current draft
    const beforeRestore = db.raw.prepare(
      'SELECT data, title FROM documents WHERE root_id = ? AND is_current_draft = 1'
    ).get(rootId)
    expect(JSON.parse(beforeRestore.data).body).toBe('completely different text')

    // Restore to version 1
    const res = await app.request(`/admin/versioning/${rootId}/restore/1`, { method: 'POST' })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.success).toBe(true)

    // After restore, the current draft should have v1's data
    const afterRestore = db.raw.prepare(
      'SELECT data, title FROM documents WHERE root_id = ? AND is_current_draft = 1'
    ).get(rootId)
    const restoredData = JSON.parse(afterRestore.data)
    expect(restoredData.body).toBe('original body text')
    expect(afterRestore.title).toBe('Original Title')
  })

  // ── Test 3: Non-existent rootId → 404 ────────────────────────────────────────
  it('returns 404 for a non-existent document', async () => {
    const res = await app.request('/admin/versioning/non-existent-root-id-xyz')
    expect(res.status).toBe(404)
  })

  // ── Test 4: Restore non-existent version → 404 ────────────────────────────────
  it('returns 404 when restoring a version that does not exist', async () => {
    const svc = makeDocService()

    const doc = await svc.create({
      typeId: VERSIONED_TYPE_ID,
      tenantId: TENANT,
      locale: 'default',
      title: 'Article',
      data: { body: 'content' },
    }, 'u1')

    const res = await app.request(`/admin/versioning/${doc.rootId}/restore/999`, { method: 'POST' })
    expect(res.status).toBe(404)
  })
})
