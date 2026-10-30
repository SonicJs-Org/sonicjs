// @ts-nocheck
// Real-SQLite proof of cross-tenant isolation at the document service/repository chokepoints that
// every content route now funnels through (after the literal-'default' sweep). If these pass, a
// tenant-A document cannot surface in a tenant-B read, and a service scoped to one tenant stamps
// that tenant on create.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../../../../__tests__/utils/d1-sqlite'
import { DocumentsService } from '../../../../services/documents'
import { DocumentRepository } from '../../../../services/document-repository'

const FIELDS = [{ name: 'rating', kind: 'scalar', type: 'integer', column: 'q_tst_rating' }]

function svc(db, tenantId) {
  return new DocumentsService(db, { queryableFields: FIELDS, tenantId, typeSchemaVersion: 1 })
}

describe('Tenant isolation — documents (real SQLite)', () => {
  let db
  beforeEach(() => {
    db = createTestD1()
    db.raw.prepare(
      `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
       VALUES ('testimonial','testimonial','Testimonial','{}','[]','{"baseGrants":{"public":["read"],"admin":["read","create","update","delete","publish","manage"]}}','system',1,1,1,1,1)`
    ).run()
  })
  afterEach(() => db.close())

  it('a service scoped to tenant A stamps tenant A on create', async () => {
    const doc = await svc(db, 'acme').create({ typeId: 'testimonial', title: 'Hi', data: { rating: 5 } }, 'u1')
    const row = db.raw.prepare('SELECT tenant_id FROM documents WHERE id=?').get(doc.id)
    expect(row.tenant_id).toBe('acme')
  })

  it("create() ignores nothing but defaults to the service tenant when input omits it", async () => {
    // No tenantId in input → falls back to the service's tenant (the unification fix).
    const doc = await svc(db, 'beta').create({ typeId: 'testimonial', title: 'X', data: {} }, 'u1')
    expect(db.raw.prepare('SELECT tenant_id t FROM documents WHERE id=?').get(doc.id).t).toBe('beta')
  })

  it('repository.list for tenant B never returns tenant A documents', async () => {
    await svc(db, 'acme').create({ typeId: 'testimonial', title: 'A-only', data: { rating: 1 } }, 'u1')
    await svc(db, 'beta').create({ typeId: 'testimonial', title: 'B-only', data: { rating: 2 } }, 'u1')

    const aRepo = new DocumentRepository(db, 'acme')
    const bRepo = new DocumentRepository(db, 'beta')

    const aDocs = await aRepo.list({ typeId: 'testimonial', status: 'all', limit: 50 })
    const bDocs = await bRepo.list({ typeId: 'testimonial', status: 'all', limit: 50 })

    expect(aDocs.map((d) => d.title)).toEqual(['A-only'])
    expect(bDocs.map((d) => d.title)).toEqual(['B-only'])
  })

  it('repository.getById is tenant-scoped: tenant B cannot fetch tenant A row by id', async () => {
    const aDoc = await svc(db, 'acme').create({ typeId: 'testimonial', title: 'Secret', data: {} }, 'u1')
    const aRepo = new DocumentRepository(db, 'acme')
    const bRepo = new DocumentRepository(db, 'beta')

    expect(await aRepo.getById(aDoc.id)).not.toBeNull()
    expect(await bRepo.getById(aDoc.id)).toBeNull()
  })

  it('default tenant is isolated from named tenants', async () => {
    await svc(db, 'default').create({ typeId: 'testimonial', title: 'Default doc', data: {} }, 'u1')
    await svc(db, 'acme').create({ typeId: 'testimonial', title: 'Acme doc', data: {} }, 'u1')

    const defaultDocs = await new DocumentRepository(db, 'default').list({ typeId: 'testimonial', status: 'all', limit: 50 })
    expect(defaultDocs.map((d) => d.title)).toEqual(['Default doc'])
  })
})
