// @ts-nocheck
// G5 — shared/global document types. A type with settings.global=true lives in one shared pool
// (GLOBAL_TENANT) and is visible from every tenant; a normal type stays tenant-isolated. The
// security-critical assertion is the negative one: a non-global type is NEVER visible cross-tenant.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../../../../__tests__/utils/d1-sqlite'
import { DocumentsService } from '../../../../services/documents'
import { DocumentRepository } from '../../../../services/document-repository'
import { effectiveTenantForType, GLOBAL_TENANT } from '../../../../services/document-request-context'

describe('Global (shared) document types — G5', () => {
  let db
  beforeEach(() => { db = createTestD1() })
  afterEach(() => db.close())

  it('effectiveTenantForType: global → GLOBAL_TENANT, otherwise the request tenant', () => {
    expect(effectiveTenantForType('acme', { global: true })).toBe(GLOBAL_TENANT)
    expect(effectiveTenantForType('acme', { global: false })).toBe('acme')
    expect(effectiveTenantForType('acme', {})).toBe('acme')
    expect(effectiveTenantForType('acme', undefined)).toBe('acme')
  })

  it('a global type is visible from every tenant; a normal type stays isolated', async () => {
    // Global-type doc — written under the shared pool (what the route does for a global type).
    const gTenant = effectiveTenantForType('acme', { global: true }) // GLOBAL_TENANT
    const gsvc = new DocumentsService(db, { tenantId: gTenant, queryableFields: [] })
    await gsvc.create({ typeId: 'global_note', tenantId: gTenant, title: 'Shared', data: {}, publishOnCreate: true })

    // Normal-type doc — written under tenant 'acme'.
    const asvc = new DocumentsService(db, { tenantId: 'acme', queryableFields: [] })
    await asvc.create({ typeId: 'blog_post', tenantId: 'acme', title: 'Acme only', data: {}, publishOnCreate: true })

    // Global note: a request from ANY tenant resolves to GLOBAL_TENANT → sees it.
    for (const reqTenant of ['acme', 'beta', 'default']) {
      const repo = new DocumentRepository(db, effectiveTenantForType(reqTenant, { global: true }))
      const titles = (await repo.list({ typeId: 'global_note', status: 'published' })).map((d) => d.title)
      expect(titles).toContain('Shared')
    }

    // Normal blog_post: visible in acme, NOT in beta — isolation preserved (the safety property).
    const acme = new DocumentRepository(db, effectiveTenantForType('acme', { global: false }))
    expect((await acme.list({ typeId: 'blog_post', status: 'published' })).map((d) => d.title)).toContain('Acme only')
    const beta = new DocumentRepository(db, effectiveTenantForType('beta', { global: false }))
    expect((await beta.list({ typeId: 'blog_post', status: 'published' })).map((d) => d.title)).not.toContain('Acme only')

    // Global docs live ONLY in the shared pool — a raw tenant-scoped read never sees them.
    const betaRaw = new DocumentRepository(db, 'beta')
    expect((await betaRaw.list({ typeId: 'global_note', status: 'published' })).map((d) => d.title)).not.toContain('Shared')
  })
})
